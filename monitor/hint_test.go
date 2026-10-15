// Copyright (C) 2026 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
//
// This file is part of SpecMon.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package monitor

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

const (
	hintTestEventName   = "hintTestEvent"
	hintTestReady       = "HintTestReady"
	hintTestStarted     = "HintTestStarted"
	hintTestDone        = "HintTestDone"
	hintTestOut         = "HintTestOut"
	hintTestExtra       = "HintTestExtra"
	hintTestMissing     = "HintTestMissing"
	hintTestHintAction  = "HintTestHintAction"
	hintTestTrigAction  = "HintTestTriggerAction"
	hintTestSeed        = "HintTestSeed"
	hintTestContinued   = "HintTestContinued"
	hintTestOtherReady  = "HintTestOtherReady"
	hintTestOtherResult = "HintTestOtherResult"
)

func hintRule(name string, lhs, rhs, actions []*rule.Fact, hints ...term.Term) *rule.Rule {
	return &rule.Rule{
		Name: name,
		LHS:  lhs,
		RHS:  rhs,
		Act:  actions,
		Attrs: map[string]rule.Attribute{
			rule.HintAttributeName: rule.TermAttribute{Value: hints},
		},
	}
}

func hintTestEvent() term.Term {
	return eventTerm(hintTestEventName, term.NewFunction(term.PairFunctionName, nil))
}

// hintTestFamily describes a hinted start, the trigger rule that continues
// it and produces Done('1'), and epsilon rules that check Done's value.
// Facts and actions carry the family's suffix.
type hintTestFamily struct {
	suffix       string
	triggerLHS   []*rule.Fact
	triggerCheck []*rule.Fact
	extra        bool
	checks       []term.Term
	invalidEnd   bool
}

func (f hintTestFamily) rules() []*rule.Rule {
	fact := func(name string, args ...term.Term) *rule.Fact {
		return rule.NewFact(name+f.suffix, args, rule.LinearFact)
	}
	x := term.NewVariable("x")
	triggerLHS := append([]*rule.Fact{fact(hintTestStarted)}, f.triggerLHS...)
	one := term.NewConstant("1")
	triggerRHS := []*rule.Fact{fact(hintTestDone, one)}
	if f.extra {
		triggerRHS = append(triggerRHS, fact(hintTestExtra, one))
	}
	rules := []*rule.Rule{
		hintRule("HintTestHint"+f.suffix, []*rule.Fact{fact(hintTestReady)}, []*rule.Fact{fact(hintTestStarted)},
			[]*rule.Fact{fact(hintTestHintAction)}, hintTestEvent()),
		triggerRule("HintTestTrigger"+f.suffix, triggerLHS, triggerRHS,
			append([]*rule.Fact{fact(hintTestTrigAction)}, f.triggerCheck...), hintTestEvent()),
	}
	for i, check := range f.checks {
		rhs := []*rule.Fact{fact(hintTestOut, x)}
		if f.invalidEnd {
			rhs = []*rule.Fact{fact(hintTestOut, term.NewFunction(term.AddFunctionName, []term.Term{x, term.NewConstant("text")}))}
		}
		rules = append(rules, epsilonRule("HintTestEnd"+f.suffix+string(rune('A'+i)),
			[]*rule.Fact{fact(hintTestDone, x)}, rhs, []*rule.Fact{equalAction(x, check)}))
	}
	if f.extra {
		rules = append(rules, epsilonRule("HintTestExtraEnd"+f.suffix, []*rule.Fact{fact(hintTestExtra, x)}, nil, nil))
	}
	return rules
}

func (f hintTestFamily) ready() *rule.Fact {
	return rule.NewFact(hintTestReady+f.suffix, nil, rule.LinearFact)
}

func TestHintContinuationEndedByEpsilonStep(t *testing.T) {
	t.Parallel()

	one := term.NewConstant("1")
	two := term.NewConstant("2")
	pruned := hintTestFamily{suffix: "Pruned", checks: []term.Term{two}}
	surviving := hintTestFamily{suffix: "Surviving", checks: []term.Term{one}}
	mixed := hintTestFamily{suffix: "Mixed", checks: []term.Term{two, one}}
	survivingConfig := factProjection(pruned.ready(), rule.NewFact(hintTestOut+surviving.suffix, []term.Term{one}, rule.LinearFact))
	survivingActions := []string{hintTestHintAction + surviving.suffix + "()\x1e" + hintTestTrigAction + surviving.suffix + "()\x1eEq('1', '1')"}

	tests := []struct {
		name         string
		families     []hintTestFamily
		wantConfigs  []string
		wantActions  []string
		wantErr      error
		wantFailures FailureCounts
	}{
		{
			name:         "pruned before surviving",
			families:     []hintTestFamily{pruned, surviving},
			wantConfigs:  []string{survivingConfig},
			wantActions:  survivingActions,
			wantFailures: FailureCounts{Restriction: 1, DeadHint: 1},
		},
		{
			name:         "surviving before pruned",
			families:     []hintTestFamily{surviving, pruned},
			wantConfigs:  []string{survivingConfig},
			wantActions:  survivingActions,
			wantFailures: FailureCounts{Restriction: 1, DeadHint: 1},
		},
		{
			name:         "mixed epsilon branches",
			families:     []hintTestFamily{mixed},
			wantConfigs:  []string{factProjection(rule.NewFact(hintTestOut+mixed.suffix, []term.Term{one}, rule.LinearFact))},
			wantActions:  []string{hintTestHintAction + mixed.suffix + "()\x1e" + hintTestTrigAction + mixed.suffix + "()\x1eEq('1', '1')"},
			wantFailures: FailureCounts{Restriction: 1},
		},
		{
			name:         "every branch pruned",
			families:     []hintTestFamily{pruned},
			wantErr:      ErrNoApplicableRule,
			wantFailures: FailureCounts{Restriction: 1, DeadHint: 1},
		},
		{
			name: "no triggered continuation",
			families: []hintTestFamily{{
				suffix: "Unmatched", checks: []term.Term{one},
				triggerLHS: []*rule.Fact{rule.NewFact(hintTestMissing, nil, rule.LinearFact)},
			}},
			wantErr:      ErrNoApplicableRule,
			wantFailures: FailureCounts{DeadHint: 1},
		},
		{
			name: "continuation restriction fails",
			families: []hintTestFamily{{
				suffix: "Restricted", checks: []term.Term{one},
				triggerCheck: []*rule.Fact{equalAction(one, two)},
			}},
			wantErr:      ErrNoApplicableRule,
			wantFailures: FailureCounts{Restriction: 1, DeadHint: 1},
		},
		{
			// Both successors of the epsilon step keep a candidate, so
			// both are pruned and the hint candidate ends.
			name:         "depth pruned",
			families:     []hintTestFamily{{suffix: "Deep", checks: []term.Term{one}, extra: true}},
			wantErr:      ErrNoApplicableRule,
			wantFailures: FailureCounts{EpsilonDepth: 2, DeadHint: 1},
		},
		{
			name:         "evaluation failure",
			families:     []hintTestFamily{{suffix: "Invalid", checks: []term.Term{one}, invalidEnd: true}},
			wantErr:      ErrNoApplicableRule,
			wantFailures: FailureCounts{Evaluation: 1, DeadHint: 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var rules []*rule.Rule
			for _, family := range test.families {
				rules = append(rules, family.rules()...)
			}
			m := newEpsilonTestMonitor(t, rules...)
			for _, family := range test.families {
				m.Configs()[0].AddFact(family.ready())
			}

			actions, err := m.ProcessEvent(hintTestEvent())
			wantFailures(t, m, test.wantFailures)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("ProcessEvent error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProcessEvent: %v", err)
			}
			if got := publicConfigProjection(m, nil); !slices.Equal(got, test.wantConfigs) {
				t.Errorf("configurations = %q, want %q", got, test.wantConfigs)
			}
			if got := actionProjection(actions); !slices.Equal(got, test.wantActions) {
				t.Errorf("actions = %q, want %q", got, test.wantActions)
			}
		})
	}
}

func TestHintBindingsCountEqualMatchesOnce(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	z := term.NewVariable("z")
	w := term.NewVariable("w")
	value := term.NewVariable("value")
	one := term.NewConstant[int64](1)
	two := term.NewConstant[int64](2)
	event := eventTerm(hintTestEventName, two)
	withArgument := func(arg, result term.Term) term.Term {
		return term.NewFunction(term.PairFunctionName, []term.Term{
			term.NewFunction(hintTestEventName, []term.Term{arg}), result,
		})
	}
	argumentEvent := withArgument(one, two)
	ready := rule.NewFact(hintTestReady, nil, rule.LinearFact)
	started := rule.NewFact(hintTestStarted, nil, rule.LinearFact)
	continued := rule.NewFact(hintTestContinued, nil, rule.LinearFact)
	continuation := triggerRule("HintTestContinuation", []*rule.Fact{started}, []*rule.Fact{continued}, nil,
		withArgument(term.NewVariable("v"), term.NewVariable("u")))
	otherReady := rule.NewFact(hintTestOtherReady, nil, rule.LinearFact)
	otherResult := rule.NewFact(hintTestOtherResult, nil, rule.LinearFact)
	otherHint := hintRule("HintTestOtherHint", []*rule.Fact{otherReady}, []*rule.Fact{started, otherResult}, nil,
		withArgument(x, y))

	identical := hintRule("HintTestIdentical", []*rule.Fact{ready}, []*rule.Fact{started}, nil,
		withArgument(x, y), withArgument(x, y))
	distinct := hintRule("HintTestDistinct", []*rule.Fact{ready}, []*rule.Fact{started}, nil,
		withArgument(x, y), withArgument(z, w))
	seed := rule.NewFact(hintTestSeed, []term.Term{value}, rule.LinearFact)
	computed := eventTerm(hintTestEventName, term.NewFunction(term.AddFunctionName, []term.Term{value, one}))
	evaluated := hintRule("HintTestEvaluated", []*rule.Fact{seed}, []*rule.Fact{started}, nil, computed, computed)
	evaluatedContinuation := triggerRule("HintTestEvaluatedContinuation", []*rule.Fact{started}, []*rule.Fact{continued}, nil,
		eventTerm(hintTestEventName, term.NewVariable("u")))

	tests := []struct {
		name        string
		rules       []*rule.Rule
		facts       []*rule.Fact
		event       term.Term
		wantConfigs []string
	}{
		{
			name:        "identical hints",
			rules:       []*rule.Rule{identical, continuation},
			facts:       []*rule.Fact{ready},
			event:       argumentEvent,
			wantConfigs: []string{factProjection(continued)},
		},
		{
			name:        "identical hints after premise instantiation",
			rules:       []*rule.Rule{evaluated, evaluatedContinuation},
			facts:       []*rule.Fact{rule.NewFact(hintTestSeed, []term.Term{one}, rule.LinearFact)},
			event:       event,
			wantConfigs: []string{factProjection(continued)},
		},
		{
			// Both bindings are explored and reach the same configuration.
			name:        "distinct bindings with equal successors",
			rules:       []*rule.Rule{distinct, continuation},
			facts:       []*rule.Fact{ready},
			event:       argumentEvent,
			wantConfigs: []string{factProjection(continued)},
		},
		{
			name:        "distinct bindings before an accepting hint",
			rules:       []*rule.Rule{distinct, otherHint, continuation},
			facts:       []*rule.Fact{ready, otherReady},
			event:       argumentEvent,
			wantConfigs: []string{factProjection(continued, otherReady), factProjection(continued, otherResult, ready)},
		},
		{
			name:        "distinct bindings after an accepting hint",
			rules:       []*rule.Rule{otherHint, distinct, continuation},
			facts:       []*rule.Fact{ready, otherReady},
			event:       argumentEvent,
			wantConfigs: []string{factProjection(continued, otherReady), factProjection(continued, otherResult, ready)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			m := newEpsilonTestMonitor(t, test.rules...)
			for _, fact := range test.facts {
				m.Configs()[0].AddFact(fact)
			}
			actions, err := m.ProcessEvent(test.event)
			if err != nil {
				t.Fatalf("ProcessEvent: %v", err)
			}
			if got := publicConfigProjection(m, nil); !slices.Equal(got, test.wantConfigs) {
				t.Errorf("configurations = %q, want %q", got, test.wantConfigs)
			}
			if len(actions) != 0 {
				t.Errorf("actions = %v, want none", actions)
			}
		})
	}
}

const hintBindingsTestFact = "HintBindingsTestP"

// hintBindingsOf returns the bindings under which the hints of a hint rule
// with premises lhs match event in a configuration with facts, in the
// order in which hintBindings returns them.
func hintBindingsOf(t *testing.T, lhs, facts []*rule.Fact, event term.Term, hints ...term.Term) []string {
	t.Helper()
	r := hintRule("HintBindingsTest", lhs, nil, nil, hints...)
	m := newEpsilonTestMonitor(t, r)
	c := NewConfig()
	for _, fact := range facts {
		c.AddFact(fact)
	}
	key, err := ruleKeyForTerm(hints[0])
	if err != nil {
		t.Fatalf("hint key: %v", err)
	}
	var got []string
	for _, b := range m.hintBindings(c, event, m.hintRules[key][0]) {
		got = append(got, b.String())
	}
	return got
}

// TestHintBindings checks the bindings of the hints of a rule: equal
// matches count once and distinct ones are all kept. A hint gives the same
// bindings whether it is matched against the event first or after its
// premise variables are substituted, and a hint that matches only after
// substitution is explored beside one that matches directly, in both hint
// orders, also when the event contains a computation at a position where
// the hint has a constant (the event is compared as unification evaluates
// it). When the hints disagree, the bindings come per premise substitution
// first, then per hint.
func TestHintBindings(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	z := term.NewVariable("z")
	r := term.NewVariable("r")
	q := term.NewVariable("q")
	w := term.NewVariable("w")
	s := term.NewVariable("s")
	three := term.NewConstant[int64](3)
	five := term.NewConstant[int64](5)
	seven := term.NewConstant[int64](7)
	premise := func(arg term.Term) *rule.Fact { return linearFact(hintBindingsTestFact, arg) }
	add := func(a, b term.Term) term.Term { return term.NewFunction(term.AddFunctionName, []term.Term{a, b}) }
	call := func(result term.Term, args ...term.Term) term.Term {
		return term.NewFunction(term.PairFunctionName, []term.Term{term.NewFunction(hintTestEventName, args), result})
	}
	ready := []*rule.Fact{rule.NewFact(hintTestReady, nil, rule.LinearFact)}
	target := eventTerm(hintTestEventName, term.NewConstant("1"))
	hint := func(v term.Term) term.Term { return eventTerm(hintTestEventName, v) }
	// Two premise substitutions, one hint that matches the event only once
	// x is substituted, and a second hint that matches with another binding.
	xs := []*rule.Fact{premise(x)}
	fourAndFive := []*rule.Fact{premise(term.NewConstant[int64](4)), premise(five)}
	direct, substituted, other := call(r, x), call(r, add(x, term.NewConstant[int64](0))), call(s, w)
	perPremise := []string{"[ r -> 7, x -> 5 ]", "[ s -> 7, w -> 5, x -> 4 ]", "[ s -> 7, w -> 5, x -> 5 ]"}
	// One premise substitution of y, a direct hint and one that matches only
	// once y is substituted.
	ys := []*rule.Fact{premise(y)}
	onlyFive := []*rule.Fact{premise(five)}
	directX, substitutedY := call(r, x), call(q, add(y, term.NewConstant[int64](0)))
	mixed := []string{"[ q -> 7, y -> 5 ]", "[ r -> 7, x -> 5, y -> 5 ]"}

	for _, test := range []struct {
		name  string
		lhs   []*rule.Fact
		facts []*rule.Fact
		event term.Term
		hints []term.Term
		want  []string
		// ordered compares the bindings in their order, not sorted.
		ordered bool
	}{
		{name: "equal matches count once", lhs: ready, facts: ready, event: target, hints: []term.Term{hint(x), hint(x)}, want: []string{"[ x -> '1' ]"}},
		{
			name: "distinct matches are both kept", lhs: ready, facts: ready, event: target, hints: []term.Term{hint(x), hint(z)},
			want: []string{"[ x -> '1' ]", "[ z -> '1' ]"},
		},
		{name: "one match", lhs: ready, facts: ready, event: target, hints: []term.Term{hint(term.NewConstant("2")), hint(x)}, want: []string{"[ x -> '1' ]"}},
		{name: "agree across paths/event first", lhs: xs, facts: fourAndFive, event: call(seven, five), hints: []term.Term{direct}, want: perPremise[:1]},
		{name: "agree across paths/after substitution", lhs: xs, facts: fourAndFive, event: call(seven, five), hints: []term.Term{substituted}, want: perPremise[:1]},
		{name: "agree across paths/per premise substitution", lhs: xs, facts: fourAndFive, event: call(seven, five), hints: []term.Term{direct, other}, want: perPremise},
		{name: "agree across paths/both paths", lhs: xs, facts: fourAndFive, event: call(seven, five), hints: []term.Term{substituted, direct}, want: perPremise[:1]},
		{name: "mix direct and substituted/direct first", lhs: ys, facts: onlyFive, event: call(seven, five), hints: []term.Term{directX, substitutedY}, want: mixed},
		{name: "mix direct and substituted/substituted first", lhs: ys, facts: onlyFive, event: call(seven, five), hints: []term.Term{substitutedY, directX}, want: mixed},
		{
			name: "order", lhs: xs, facts: fourAndFive, event: call(seven, five),
			hints: []term.Term{call(s, w), call(term.NewVariable("u"), term.NewVariable("v"))}, ordered: true,
			want: []string{"[ s -> 7, w -> 5, x -> 4 ]", "[ u -> 7, v -> 5, x -> 4 ]", "[ s -> 7, w -> 5, x -> 5 ]", "[ u -> 7, v -> 5, x -> 5 ]"},
		},
		{
			name: "compare the evaluated event", lhs: ys, facts: onlyFive, event: call(seven, add(term.NewConstant[int64](1), term.NewConstant[int64](2)), five),
			hints: []term.Term{call(r, x, z), call(q, three, add(y, term.NewConstant[int64](0)))},
			want:  []string{"[ q -> 7, y -> 5 ]", "[ r -> 7, x -> 3, y -> 5, z -> 5 ]"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := hintBindingsOf(t, test.lhs, test.facts, test.event, test.hints...)
			if !test.ordered {
				slices.Sort(got)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("hint bindings = %q, want %q", got, test.want)
			}
		})
	}
}

const (
	hintAltCallName   = "hintAltCall"
	hintAltResultName = "hintAltResult"
	hintAltStartName  = "hintAltStart"
	hintAltFinishName = "hintAltFinish"
	hintAltSetupName  = "hintAltSetup"
	hintAltOutputName = "hintAltOutput"
	hintAltReady      = "HintAltReady"
	hintAltStarted    = "HintAltStarted"
	hintAltDone       = "HintAltDone"
	hintAltOut        = "HintAltOut"
	hintAltSeed       = "HintAltSeed"
	hintAltState      = "HintAltState"
	hintAltIn         = "HintAltIn"
	hintAltProduct    = "HintAltProduct"
	hintAltRule       = "HintAlt"
	hintAltNative     = "HintAltNative"
	hintAltFamily     = "HintAltFamily"
)

// hintAltCall returns the event <hintAltCall(args...), result>.
func hintAltCall(result term.Term, args ...term.Term) term.Term {
	return term.NewFunction(term.PairFunctionName, []term.Term{term.NewFunction(hintAltCallName, args), result})
}

// hintAltSwapped returns the hints <hintAltCall(a, b), r> and
// <hintAltCall(b, a), r>, which match one call with distinct bindings, in
// the given order.
func hintAltSwapped(reversed bool) []term.Term {
	a := term.NewVariable("a")
	b := term.NewVariable("b")
	r := term.NewVariable("r")
	hints := []term.Term{hintAltCall(r, a, b), hintAltCall(r, b, a)}
	if reversed {
		slices.Reverse(hints)
	}
	return hints
}

func hintAltOrders() map[string]bool {
	return map[string]bool{"hint order": false, "reversed hint order": true}
}

// hintAltEvent returns the call <hintAltCall('1', '2'), '3'>, which both
// hints of hintAltSwapped match.
func hintAltEvent() term.Term {
	return hintAltCall(term.NewConstant("3"), term.NewConstant("1"), term.NewConstant("2"))
}

// hintAltAnyCall returns a trigger that matches every call of
// hintAltCall with two arguments.
func hintAltAnyCall() term.Term {
	return hintAltCall(term.NewVariable("w"), term.NewVariable("u"), term.NewVariable("v"))
}

// TestHintAlternatives checks that the two alternatives of a hint rule
// whose hints match one event with distinct bindings are explored on their
// own, in both hint orders: each keeps its successors and actions, an
// alternative without a continuation ends alone with its own reason, and
// alternatives that reach the same hinted state share its continuations.
func TestHintAlternatives(t *testing.T) {
	t.Parallel()

	a, b, x, y := term.NewVariable("a"), term.NewVariable("b"), term.NewVariable("x"), term.NewVariable("y")
	one, two := term.NewConstant("1"), term.NewConstant("2")
	ready, started, done := linearFact(hintAltReady), linearFact(hintAltStarted), linearFact(hintAltDone)
	startedAB := []*rule.Fact{linearFact(hintAltStarted, a, b)}
	continuation := func(trigger term.Term) *rule.Rule {
		return triggerRule(hintAltRule+"Continue", []*rule.Fact{linearFact(hintAltStarted, x, y)},
			[]*rule.Fact{linearFact(hintAltDone, x, y)}, nil, trigger)
	}
	// The continuations of the started state without arguments. The
	// second always fails its restriction.
	output := triggerRule(hintAltRule+"Output", []*rule.Fact{started}, []*rule.Fact{done}, []*rule.Fact{linearFact(hintAltOut)}, hintAltAnyCall())
	restricted := triggerRule(hintAltRule+"Restricted", []*rule.Fact{started}, []*rule.Fact{done},
		[]*rule.Fact{equalAction(one, two)}, hintAltAnyCall())

	for _, test := range []struct {
		name          string
		rhs, actions  []*rule.Fact
		continuations []*rule.Rule
		// wantConfigs is nil if the event is rejected.
		wantConfigs  []string
		wantActions  []string
		wantFailures FailureCounts
	}{
		{
			name: "distinct bindings", rhs: startedAB, continuations: []*rule.Rule{continuation(hintAltAnyCall())},
			wantConfigs: []string{factProjection(linearFact(hintAltDone, one, two)), factProjection(linearFact(hintAltDone, two, one))},
		},
		{
			name: "equal states with different outputs", rhs: []*rule.Fact{started}, actions: []*rule.Fact{linearFact(hintAltOut, a, b)},
			continuations: []*rule.Rule{output}, wantConfigs: []string{factProjection(done)},
			wantActions: []string{hintAltOut + "('1', '2')\x1e" + hintAltOut + "()", hintAltOut + "('2', '1')\x1e" + hintAltOut + "()"},
		},
		{
			// The continuation consumes the call only with the arguments in
			// the order of the started state.
			name: "one dead", rhs: startedAB, continuations: []*rule.Rule{continuation(hintAltCall(term.NewVariable("w"), x, y))},
			wantConfigs: []string{factProjection(linearFact(hintAltDone, one, two))}, wantFailures: FailureCounts{DeadHint: 1},
		},
		{name: "all dead", rhs: startedAB, wantFailures: FailureCounts{DeadHint: 2}},
		{
			name: "separately attempted continuations", rhs: []*rule.Fact{started}, continuations: []*rule.Rule{output, restricted},
			wantConfigs: []string{factProjection(done)}, wantActions: []string{hintAltOut + "()", hintAltOut + "()"},
			wantFailures: FailureCounts{Restriction: 2},
		},
		{
			name: "dead alternatives each try a failing continuation", rhs: []*rule.Fact{started}, continuations: []*rule.Rule{restricted},
			wantFailures: FailureCounts{Restriction: 2, DeadHint: 2},
		},
	} {
		for name, reversed := range hintAltOrders() {
			t.Run(test.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				start := hintRule(hintAltRule+"Start", []*rule.Fact{ready}, test.rhs, test.actions, hintAltSwapped(reversed)...)
				m, actions, err := runEvents(t, append([]*rule.Rule{start}, test.continuations...), []*rule.Fact{ready}, hintAltEvent())
				wantFailures(t, m, test.wantFailures)
				if test.wantFailures.Restriction == 2 {
					var records []FailureRecord
					for _, record := range m.FailureReport().Final {
						if record.Category == FailureRestriction {
							records = append(records, record)
						}
					}
					if len(records) != 2 || records[0].Rule != records[1].Rule || records[0].Message != records[1].Message || records[0].Branch != records[1].Branch {
						t.Fatalf("per-binding restriction records = %v", records)
					}
				}
				if test.wantConfigs == nil {
					wantRejected(t, m, err)
					return
				}
				if err != nil {
					t.Fatalf("ProcessEvent: %v", err)
				}
				wantConfigs(t, m, test.wantConfigs...)
				if test.wantActions != nil {
					wantActions(t, actions, test.wantActions...)
				}
			})
		}
	}
}

// TestHintSuppressionPerBinding checks the priority of a direct
// continuation per hint binding. Two hints of one start rule match the
// event under the same premise values with distinct bindings, and a valid
// direct continuation of that family has the binding of the first one
// only. The first alternative is suppressed. The second and its
// continuation are kept. Premises are persistent or linear copies of
// equal value, and the hints come in both orders.
func TestHintSuppressionPerBinding(t *testing.T) {
	t.Parallel()

	k1 := term.NewVariable("k1")
	k2 := term.NewVariable("k2")
	r1 := term.NewVariable("r1")
	r2 := term.NewVariable("r2")
	one := term.NewConstant("1")
	five := term.NewConstant("5")
	state := linearFact(hintAltState, one, one)
	done := linearFact(hintAltDone, one, one, five)
	continuation := triggerRule(hintAltFamily+rule.ComponentSep+"0", []*rule.Fact{linearFact(hintAltState, k1, k2)},
		[]*rule.Fact{linearFact(hintAltDone, k1, k2, r1)}, nil, hintAltCall(r1, k1))

	for _, kind := range []rule.FactType{rule.PersistentFact, rule.LinearFact} {
		seed := rule.NewFact(hintAltSeed, []term.Term{one, one}, kind)
		facts := []*rule.Fact{seed, state}
		hinted := factProjection(seed, state, done)
		if kind == rule.LinearFact {
			facts = append(facts, seed)
		}
		for name, reversed := range hintAltOrders() {
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				t.Parallel()
				hints := []term.Term{hintAltCall(r1, k1), hintAltCall(r2, k2)}
				if reversed {
					slices.Reverse(hints)
				}
				start := hintRule(hintAltFamily+rule.ComponentSep+rule.StartRuleSuffix,
					[]*rule.Fact{rule.NewFact(hintAltSeed, []term.Term{k1, k2}, kind)}, []*rule.Fact{linearFact(hintAltState, k1, k2)},
					[]*rule.Fact{linearFact(hintAltOut)}, hints...)
				m, actions := acceptEvents(t, []*rule.Rule{start, continuation}, facts, hintAltCall(five, one))
				// The direct continuation and the second alternative, whose
				// start alone publishes its action.
				want := []string{factProjection(slices.Concat(facts[:1], facts[2:], []*rule.Fact{done})...), hinted}
				slices.Sort(want)
				wantConfigs(t, m, want...)
				wantActions(t, actions, hintAltOut+"()")
			})
		}
	}
}

// TestGeneratedHintRuleWithEqualPremises checks a start rule generated for
// two computations of the same call. With equal premise values both hints
// match each call with distinct bindings, so both alternatives and both
// mid rules continue. With distinct values only one hint matches.
func TestGeneratedHintRuleWithEqualPremises(t *testing.T) {
	t.Parallel()

	k1 := term.NewVariable("k1")
	k2 := term.NewVariable("k2")
	call := func(name string, args ...term.Term) term.Term { return term.NewFunction(name, args) }
	source := &rule.Rule{
		Name: hintAltRule,
		LHS:  []*rule.Fact{linearFact(hintAltIn, k1, k2)},
		RHS: []*rule.Fact{linearFact(hintAltProduct,
			call(hintAltResultName, call(hintAltCallName, k1), call(hintAltCallName, k2)))},
		Attrs: map[string]rule.Attribute{},
	}
	rules := rule.Translate(source)
	if !slices.ContainsFunc(rules, func(r *rule.Rule) bool { return len(r.Hints()) == 2 }) {
		t.Fatalf("translation %v has no start rule with two hints", rules)
	}
	event := func(name string, result term.Term, args ...term.Term) term.Term {
		return term.NewFunction(term.PairFunctionName, []term.Term{call(name, args...), result})
	}
	one := term.NewConstant[int64](1)
	two := term.NewConstant[int64](2)
	five := term.NewConstant[int64](5)
	six := term.NewConstant[int64](6)
	nine := term.NewConstant[int64](9)

	for _, test := range []struct {
		name   string
		in     *rule.Fact
		events []term.Term
	}{
		{
			name: "equal premise values",
			in:   linearFact(hintAltIn, one, one),
			events: []term.Term{
				event(hintAltCallName, five, one), event(hintAltCallName, five, one), event(hintAltResultName, nine, five, five),
			},
		},
		{
			name: "distinct premise values",
			in:   linearFact(hintAltIn, one, two),
			events: []term.Term{
				event(hintAltCallName, five, one), event(hintAltCallName, six, two), event(hintAltResultName, nine, five, six),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			m, _ := acceptEvents(t, rules, []*rule.Fact{test.in}, test.events...)
			wantConfigs(t, m, factProjection(linearFact(hintAltProduct, nine)))
			wantFailures(t, m, FailureCounts{})
		})
	}
}

// TestHintAlternativesKeepPendingApplications checks that every hint
// alternative keeps the pending native application of its configuration.
func TestHintAlternativesKeepPendingApplications(t *testing.T) {
	t.Parallel()

	a := term.NewVariable("a")
	b := term.NewVariable("b")
	x := term.NewVariable("x")
	y := term.NewVariable("y")
	unit := term.NewFunction(term.PairFunctionName, nil)
	ready := linearFact(hintAltReady)
	native := triggerRule(hintAltNative, nil, nil, nil, eventTerm(hintAltStartName, unit), eventTerm(hintAltFinishName, unit))
	start := hintRule(hintAltRule+"Start", []*rule.Fact{ready}, []*rule.Fact{linearFact(hintAltStarted, a, b)}, nil, hintAltSwapped(false)...)
	continuation := triggerRule(hintAltRule+"Continue", []*rule.Fact{linearFact(hintAltStarted, x, y)},
		[]*rule.Fact{linearFact(hintAltDone, x, y)}, nil, hintAltAnyCall())

	m, _ := acceptEvents(t, []*rule.Rule{native, start, continuation}, []*rule.Fact{ready}, eventTerm(hintAltStartName, unit), hintAltEvent())
	configs := m.Configs()
	if len(configs) != 2 {
		t.Fatalf("configurations = %v, want one per alternative", configs)
	}
	for _, config := range configs {
		if len(config.pending) != 1 || m.rules[config.pending[0].ruleOrdinal] != native {
			t.Errorf("pending applications of %v = %v, want the started one", config, config.pending)
		}
	}
}

// TestRunPipelineKeepsHintAlternativesPaired checks that the outputs of
// two hint alternatives of a rewrite rule stay paired with their own
// rewrite branch: the main monitor accepts the output of one of them, and
// only that output is consumed.
func TestRunPipelineKeepsHintAlternativesPaired(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	w := term.NewVariable("w")
	output := func(result term.Term, args ...term.Term) term.Term {
		return term.NewFunction(term.PairFunctionName, []term.Term{term.NewFunction(hintAltOutputName, args), result})
	}
	ready := rule.NewFact(hintAltReady, nil, rule.PersistentFact)
	setup := eventTerm(hintAltSetupName, term.NewFunction(term.PairFunctionName, nil))
	one, two, three := term.NewConstant("1"), term.NewConstant("2"), term.NewConstant("3")
	accepted := output(three, one, two)

	for name, reversed := range hintAltOrders() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rewriter := newEpsilonTestMonitor(t,
				triggerRule("PipelineHintSetup", nil, []*rule.Fact{ready}, nil, setup),
				hintRule("PipelineHintStart", []*rule.Fact{ready}, []*rule.Fact{linearFact(hintAltStarted, term.NewVariable("a"), term.NewVariable("b"))},
					nil, hintAltSwapped(reversed)...),
				triggerRule("PipelineHintContinue", []*rule.Fact{linearFact(hintAltStarted, x, y)}, nil,
					[]*rule.Fact{rule.NewFact(rule.RewriteEventName, []term.Term{output(w, x, y)}, rule.LinearFact)},
					hintAltAnyCall()))
			main := newEpsilonTestMonitor(t, triggerRule("PipelineHintMain", nil, []*rule.Fact{linearFact(hintAltDone)}, nil, accepted))

			var consumed []term.Term
			violation, err := RunPipeline(context.Background(), rewriter, main, failureTrace(t, setup, hintAltCall(three, one, two)),
				func(event term.Term) error {
					consumed = append(consumed, event)
					return nil
				})
			if violation != nil || err != nil {
				t.Fatalf("RunPipeline = (%v, %v), want acceptance", violation, err)
			}
			if len(consumed) != 1 || !consumed[0].Equal(accepted) {
				t.Fatalf("consumed = %v, want [%s]", consumed, accepted)
			}
			if configs := main.Configs(); len(configs) != 1 || configs[0].CountByName(hintAltDone) != 1 {
				t.Fatalf("main configurations = %v, want the accepted branch", configs)
			}
			if configs := rewriter.Configs(); len(configs) != 1 {
				t.Fatalf("rewrite configurations = %v, want the branch paired with the accepted output", configs)
			}
		})
	}
}

// TestPremiseVariablesTakeTheirFactValues checks that a premise variable
// takes the value of its fact, as when the premises are matched before the
// event, whether the rule has one hint, two hints that match with different
// bindings, or a trigger. The event's value is equal as bytes but may have
// another type, which the concluded fact and a string field show. A fact
// whose value has another type than the event's is still tried. A premise
// that only the event's value could match is refused at load.
func TestPremiseVariablesTakeTheirFactValues(t *testing.T) {
	t.Parallel()

	x, y, z, w, v := term.NewVariable("x"), term.NewVariable("y"), term.NewVariable("z"), term.NewVariable("w"), term.NewVariable("v")
	one := term.NewConstant[int64](1)
	field := func(kind term.FormatType, args ...term.Term) term.Term { return term.NewFunction(string(kind), args) }
	cat := func(fields ...term.Term) term.Term { return term.NewFunction(term.CatFunctionName, fields) }
	call := func(arg term.Term) term.Term { return eventTerm("premiseValueCall", arg) }
	afterOne := func(last term.Term) term.Term { return cat(field(term.FormatByteType, y, one), last) }
	annotations := map[string][]term.Term{
		"one hint": {call(x)}, "other hint": {call(z)}, "both hints": {call(x), call(z)}, "both hints reversed": {call(z), call(x)}, "trigger": nil,
	}
	// rules seeds PremiseValueState(v) and concludes PremiseValueDone of
	// conclusion from it on <premiseValueCall(), x>: directly with a
	// trigger, or with hints and a continuation.
	rules := func(premise, conclusion term.Term, hints []term.Term) []*rule.Rule {
		seed := triggerRule("PremiseValueSeed", nil, []*rule.Fact{linearFact("PremiseValueState", v)}, nil, eventTerm("premiseValueSeed", v))
		state := []*rule.Fact{linearFact("PremiseValueState", premise)}
		if hints == nil {
			return []*rule.Rule{seed, triggerRule("PremiseValueStart", state, []*rule.Fact{linearFact("PremiseValueDone", conclusion)}, nil, call(x))}
		}
		hinted := []*rule.Fact{linearFact("PremiseValueHinted", x)}
		return []*rule.Rule{
			seed,
			hintRule("PremiseValueStart", state, []*rule.Fact{linearFact("PremiseValueHinted", conclusion)}, nil, hints...),
			triggerRule("PremiseValueFollow", hinted, []*rule.Fact{linearFact("PremiseValueDone", x)}, nil, call(w)),
		}
	}

	for annotation, hints := range annotations {
		add := term.NewFunction(term.AddFunctionName, []term.Term{x, one})
		if _, err := NewMonitor(rules(add, x, hints)); err == nil {
			t.Errorf("%s: premise PremiseValueState(%s) loaded", annotation, add)
		}
	}

	for _, test := range []struct {
		name                string
		premise, conclusion term.Term
		seed                []byte
		arg                 term.Term
		want                string
	}{
		{"bytes for an int", afterOne(field(term.FormatByteType, x)), x, []byte{1, 2, 0, 0, 0, 0, 0, 0, 0}, term.NewConstant[int64](2), "PremiseValueDone(0x0200000000000000)"},
		// A string field takes only a string constant.
		{"bytes for a string", afterOne(field(term.FormatByteType, x)), cat(field(term.FormatStringType, x)), []byte{1, 'a', 'b'}, term.NewConstant("ab"), "rejected"},
		{"string for bytes", afterOne(field(term.FormatStringType, x)), x, []byte{1, 'a', 'b'}, term.NewConstant([]byte("ab")), "PremiseValueDone('ab')"},
	} {
		for annotation, hints := range annotations {
			t.Run(test.name+"/"+annotation, func(t *testing.T) {
				t.Parallel()
				m := newEpsilonTestMonitor(t, rules(test.premise, test.conclusion, hints)...)
				if _, err := m.ProcessEvent(eventTerm("premiseValueSeed", term.NewConstant(test.seed))); err != nil {
					t.Fatalf("ProcessEvent(seed): %v", err)
				}
				got := "rejected"
				if _, err := m.ProcessEvent(call(test.arg)); err == nil {
					var done []string
					for _, c := range m.Configs() {
						for _, f := range c.Facts() {
							if f.Name == "PremiseValueDone" {
								done = append(done, f.String())
							}
						}
					}
					got = strings.Join(done, " ")
				} else if !errors.Is(err, ErrNoApplicableRule) {
					t.Fatalf("ProcessEvent: %v", err)
				}
				if got != test.want {
					t.Fatalf("outcome %s, want %s", got, test.want)
				}
			})
		}
	}
}

func TestHintContinuationsPreserveConstantKinds(t *testing.T) {
	x, id := term.NewVariable("x"), term.NewVariable("id")
	unit := term.NewFunction(term.PairFunctionName, nil)
	setup, input := eventTerm("typedHintSetup", unit), eventTerm("typedHintInput", unit)
	pf := func(value, id term.Term) *rule.Fact {
		return rule.NewFact("Seed", []term.Term{value, id}, rule.PersistentFact)
	}
	qf := func(value term.Term) *rule.Fact { return rule.NewFact("Temp", []term.Term{value}, rule.LinearFact) }
	hint := &rule.Rule{Name: "Hint", LHS: []*rule.Fact{pf(x, id)}, RHS: []*rule.Fact{qf(x)}, Attrs: map[string]rule.Attribute{rule.HintAttributeName: rule.TermAttribute{Value: []term.Term{input}}}}
	next := triggerRule("Continue", []*rule.Fact{qf(x)}, nil, []*rule.Fact{rule.NewFact(rule.RewriteEventName, []term.Term{eventTerm("typedHintOutput", x)}, rule.LinearFact)}, input)
	m, err := NewMonitor([]*rule.Rule{
		triggerRule("Setup", nil, []*rule.Fact{pf(term.NewConstant("a"), term.NewConstant[int64](1)), pf(term.NewConstant([]byte("a")), term.NewConstant[int64](2))}, nil, setup), hint, next,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.processEvent(setup); err != nil {
		t.Fatal(err)
	}
	apps, err := m.processEvent(input)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range apps {
		t.Logf("application %d actions %v", i, a.actions)
	}
	if len(apps) != 2 {
		t.Fatalf("applications=%d, want2", len(apps))
	}
	_, err = rewriteOutputSequence(input, apps)
	if !errors.Is(err, ErrNondeterministicRewrite) {
		t.Fatalf("rewriteOutputSequence error=%v, want typed nondeterminism", err)
	}
}

func TestHintContinuationsKeepSuccessfulTypedBranch(t *testing.T) {
	x, id := term.NewVariable("x"), term.NewVariable("id")
	unit := term.NewFunction(term.PairFunctionName, nil)
	setup, input := eventTerm("typedHintSetup", unit), eventTerm("typedHintInput", unit)
	pf := func(value, id term.Term) *rule.Fact {
		return rule.NewFact("Seed", []term.Term{value, id}, rule.PersistentFact)
	}
	qf := func(value term.Term) *rule.Fact { return rule.NewFact("Temp", []term.Term{value}, rule.LinearFact) }
	hint := &rule.Rule{Name: "Hint", LHS: []*rule.Fact{pf(x, id)}, RHS: []*rule.Fact{qf(x)}, Attrs: map[string]rule.Attribute{rule.HintAttributeName: rule.TermAttribute{Value: []term.Term{input}}}}
	next := triggerRule("Continue", []*rule.Fact{qf(x)}, nil, []*rule.Fact{rule.NewFact("Observed", []term.Term{term.NewFunction(term.NotFunctionName, []term.Term{x})}, rule.LinearFact)}, input)
	m, err := NewMonitor([]*rule.Rule{
		triggerRule("Setup", nil, []*rule.Fact{pf(term.NewConstant("a"), term.NewConstant[int64](1)), pf(term.NewConstant([]byte("a")), term.NewConstant[int64](2))}, nil, setup), hint, next,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ProcessEvent(setup); err != nil {
		t.Fatal(err)
	}
	actions, err := m.ProcessEvent(input)
	if err != nil {
		t.Fatalf("ProcessEvent=%v, want successful bytes alternative", err)
	}
	if len(actions) != 1 {
		t.Fatalf("actions=%v, want one valid alternative", actions)
	}
	t.Logf("surviving actions=%v", actions)
}
