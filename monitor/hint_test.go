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
		wantErrParts []string
		wantNoParts  []string
	}{
		{
			name:        "pruned before surviving",
			families:    []hintTestFamily{pruned, surviving},
			wantConfigs: []string{survivingConfig},
			wantActions: survivingActions,
		},
		{
			name:        "surviving before pruned",
			families:    []hintTestFamily{surviving, pruned},
			wantConfigs: []string{survivingConfig},
			wantActions: survivingActions,
		},
		{
			name:        "mixed epsilon branches",
			families:    []hintTestFamily{mixed},
			wantConfigs: []string{factProjection(rule.NewFact(hintTestOut+mixed.suffix, []term.Term{one}, rule.LinearFact))},
			wantActions: []string{hintTestHintAction + mixed.suffix + "()\x1e" + hintTestTrigAction + mixed.suffix + "()\x1eEq('1', '1')"},
		},
		{
			name:        "every branch pruned",
			families:    []hintTestFamily{pruned},
			wantErr:     ErrNoApplicableRule,
			wantNoParts: []string{"after accepting hint"},
		},
		{
			name: "no triggered continuation",
			families: []hintTestFamily{{
				suffix: "Unmatched", checks: []term.Term{one},
				triggerLHS: []*rule.Fact{rule.NewFact(hintTestMissing, nil, rule.LinearFact)},
			}},
			wantErr:      ErrNoApplicableRule,
			wantErrParts: []string{"after accepting hint"},
		},
		{
			name: "continuation restriction fails",
			families: []hintTestFamily{{
				suffix: "Restricted", checks: []term.Term{one},
				triggerCheck: []*rule.Fact{equalAction(one, two)},
			}},
			wantErr:      ErrNoApplicableRule,
			wantErrParts: []string{"after accepting hint"},
		},
		{
			name:     "depth error",
			families: []hintTestFamily{{suffix: "Deep", checks: []term.Term{one}, extra: true}},
			wantErr:  ErrEpsilonDepth,
		},
		{
			name:     "evaluation error",
			families: []hintTestFamily{{suffix: "Invalid", checks: []term.Term{one}, invalidEnd: true}},
			wantErr:  term.ErrEvaluation,
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
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("ProcessEvent error = %v, want %v", err, test.wantErr)
				}
				for _, part := range test.wantErrParts {
					if !strings.Contains(err.Error(), part) {
						t.Fatalf("ProcessEvent error = %q, want %q", err, part)
					}
				}
				for _, part := range test.wantNoParts {
					if strings.Contains(err.Error(), part) {
						t.Fatalf("ProcessEvent error = %q, want no %q", err, part)
					}
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
		wantErr     error
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
			name:    "distinct bindings with equal successors",
			rules:   []*rule.Rule{distinct, continuation},
			facts:   []*rule.Fact{ready},
			event:   argumentEvent,
			wantErr: ErrNoApplicableRule,
		},
		{
			name:        "distinct bindings before an accepting hint",
			rules:       []*rule.Rule{distinct, otherHint, continuation},
			facts:       []*rule.Fact{ready, otherReady},
			event:       argumentEvent,
			wantConfigs: []string{factProjection(continued, otherResult, ready)},
		},
		{
			name:        "distinct bindings after an accepting hint",
			rules:       []*rule.Rule{otherHint, distinct, continuation},
			facts:       []*rule.Fact{ready, otherReady},
			event:       argumentEvent,
			wantConfigs: []string{factProjection(continued, otherResult, ready)},
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
			if len(actions) != 0 {
				t.Errorf("actions = %v, want none", actions)
			}
		})
	}
}

func TestGetUniqueBinding(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	z := term.NewVariable("z")
	target := eventTerm(hintTestEventName, term.NewConstant("1"))
	hint := func(v term.Term) term.Term { return eventTerm(hintTestEventName, v) }

	if b, err := getUniqueBinding([]term.Term{hint(x), hint(x)}, target); err != nil || b.Size() != 1 {
		t.Fatalf("equal matches = %v, %v; want one binding", b, err)
	}
	if b, err := getUniqueBinding([]term.Term{hint(x), hint(z)}, target); err == nil {
		t.Fatalf("distinct matches = %v, want an error", b)
	}
	if b, err := getUniqueBinding([]term.Term{hint(term.NewConstant("2")), hint(x)}, target); err != nil || b.Size() != 1 {
		t.Fatalf("one match = %v, %v; want one binding", b, err)
	}
}
