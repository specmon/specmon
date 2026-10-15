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
	epsilonTestEventName    = "epsilonTestGo"
	epsilonTestTriggerName  = "EpsilonTestTrigger"
	epsilonTestTriggerName2 = "EpsilonTestTriggerOther"
	epsilonTestFactA        = "EpsilonTestA"
	epsilonTestFactB        = "EpsilonTestB"
	epsilonTestFactC        = "EpsilonTestC"
	epsilonTestFactD        = "EpsilonTestD"
	epsilonTestFactP        = "EpsilonTestP"
	epsilonTestTriggered    = "EpsilonTestTriggered"
	epsilonTestActionB      = "EpsilonTestActionB"
	epsilonTestActionC      = "EpsilonTestActionC"
	epsilonTestActionUsed   = "EpsilonTestUsed"
	epsilonTestFunction     = "epsilonTestH"
	epsilonTestState        = rule.SubtermName + rule.ComponentSep + "EpsilonTestState"
)

func epsilonTestEvent() term.Term {
	return eventTerm(epsilonTestEventName, term.NewFunction(term.PairFunctionName, nil))
}

// epsilonTestTrigger returns a rule that consumes the test event, emits
// the action EpsilonTestTriggered and produces facts.
func epsilonTestTrigger(name string, facts ...*rule.Fact) *rule.Rule {
	return triggerRule(name, nil, facts,
		[]*rule.Fact{rule.NewFact(epsilonTestTriggered, nil, rule.LinearFact)},
		epsilonTestEvent())
}

func linearFact(name string, args ...term.Term) *rule.Fact {
	return rule.NewFact(name, args, rule.LinearFact)
}

// persistentP returns the persistent fact EpsilonTestP(value).
func persistentP(value term.Term) *rule.Fact {
	return rule.NewFact(epsilonTestFactP, []term.Term{value}, rule.PersistentFact)
}

func equalAction(left, right term.Term) *rule.Fact {
	return rule.NewFact("Eq", []term.Term{left, right}, rule.LinearFact)
}

func newEpsilonTestMonitor(t *testing.T, rules ...*rule.Rule) *Monitor {
	t.Helper()
	m, err := NewMonitor(rules)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	return m
}

func TestProcessEventEpsilonBranches(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	one := term.NewConstant("1")
	two := term.NewConstant("2")
	triggered := epsilonTestTriggered + "()"

	tests := []struct {
		name        string
		rules       []*rule.Rule
		wantConfigs []string
		wantActions []string
		wantErr     error
	}{
		{
			name: "no candidate",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactC, one)),
				epsilonRule("EpsilonTestPromote", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
			},
			wantConfigs: []string{factProjection(linearFact(epsilonTestFactC, one))},
			wantActions: []string{triggered},
		},
		{
			name: "all candidates fail",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, one)),
				epsilonRule("EpsilonTestCheck", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)},
					[]*rule.Fact{equalAction(x, two)}),
			},
			wantErr: ErrNoApplicableRule,
		},
		{
			name: "one candidate fails and one survives",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, one)),
				epsilonRule("EpsilonTestCheckOne", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)},
					[]*rule.Fact{equalAction(x, one)}),
				epsilonRule("EpsilonTestCheckTwo", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactC, x)},
					[]*rule.Fact{equalAction(x, two)}),
			},
			wantConfigs: []string{factProjection(linearFact(epsilonTestFactB, one))},
			wantActions: []string{triggered + "\x1eEq('1', '1')"},
		},
		{
			name: "rules sharing a linear premise branch",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, one)),
				epsilonRule("EpsilonTestToB", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)},
					[]*rule.Fact{linearFact(epsilonTestActionB)}),
				epsilonRule("EpsilonTestToC", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactC, x)},
					[]*rule.Fact{linearFact(epsilonTestActionC)}),
			},
			wantConfigs: []string{
				factProjection(linearFact(epsilonTestFactB, one)),
				factProjection(linearFact(epsilonTestFactC, one)),
			},
			wantActions: []string{
				triggered + "\x1e" + epsilonTestActionB + "()",
				triggered + "\x1e" + epsilonTestActionC + "()",
			},
		},
		{
			name: "bindings with identical successors merge",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName,
					linearFact(epsilonTestFactA, one), persistentP(one), persistentP(two)),
				epsilonRule("EpsilonTestIgnoreP", []*rule.Fact{linearFact(epsilonTestFactA, x), persistentP(y)},
					[]*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
			},
			wantConfigs: []string{factProjection(
				linearFact(epsilonTestFactB, one), persistentP(one), persistentP(two))},
			wantActions: []string{triggered},
		},
		{
			name: "bindings with distinct actions stay apart",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName,
					linearFact(epsilonTestFactA, one), persistentP(one), persistentP(two)),
				epsilonRule("EpsilonTestUseP", []*rule.Fact{linearFact(epsilonTestFactA, x), persistentP(y)},
					[]*rule.Fact{linearFact(epsilonTestFactB, x)}, []*rule.Fact{linearFact(epsilonTestActionUsed, y)}),
			},
			wantConfigs: []string{factProjection(
				linearFact(epsilonTestFactB, one), persistentP(one), persistentP(two))},
			wantActions: []string{
				triggered + "\x1e" + epsilonTestActionUsed + "('1')",
				triggered + "\x1e" + epsilonTestActionUsed + "('2')",
			},
		},
		{
			name: "failing candidate ends only its branch",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, one)),
				epsilonTestTrigger(epsilonTestTriggerName2, linearFact(epsilonTestFactA, two)),
				epsilonRule("EpsilonTestEnd", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)},
					[]*rule.Fact{equalAction(x, one)}),
			},
			wantConfigs: []string{factProjection(linearFact(epsilonTestFactB, one))},
			wantActions: []string{triggered + "\x1eEq('1', '1')"},
		},
		{
			name: "independent candidates",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, one), linearFact(epsilonTestFactC, one)),
				epsilonRule("EpsilonTestFromA", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
				epsilonRule("EpsilonTestFromC", []*rule.Fact{linearFact(epsilonTestFactC, x)}, []*rule.Fact{linearFact(epsilonTestFactD, x)}, nil),
			},
			wantErr: ErrEpsilonDepth,
		},
		{
			name: "residual failing candidate",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, one), linearFact(epsilonTestFactC, one)),
				epsilonRule("EpsilonTestFromA", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
				epsilonRule("EpsilonTestFailingC", []*rule.Fact{linearFact(epsilonTestFactC, x)}, []*rule.Fact{linearFact(epsilonTestFactD, x)},
					[]*rule.Fact{equalAction(x, two)}),
			},
			wantErr: ErrEpsilonDepth,
		},
		{
			name: "two linear occurrences",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, one), linearFact(epsilonTestFactA, two)),
				epsilonRule("EpsilonTestPromote", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
			},
			wantErr: ErrEpsilonDepth,
		},
		{
			name: "two value-equal copies",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, one), linearFact(epsilonTestFactA, one)),
				epsilonRule("EpsilonTestPromote", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
			},
			wantErr: ErrEpsilonDepth,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			m := newEpsilonTestMonitor(t, test.rules...)
			actions, err := m.ProcessEvent(epsilonTestEvent())
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

// TestHandleEpsilonReportsChainedCandidate checks the depth check at run
// time. The static condition rejects a rule set with chained epsilon
// rules, so the second rule is added after construction.
func TestHandleEpsilonReportsChainedCandidate(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	m := newEpsilonTestMonitor(t,
		epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactA, term.NewConstant("1"))),
		epsilonRule("EpsilonTestFirst", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil))
	chained := epsilonRule("EpsilonTestSecond", []*rule.Fact{linearFact(epsilonTestFactB, x)}, []*rule.Fact{linearFact(epsilonTestFactC, x)}, nil)
	m.epsilonRules = append(m.epsilonRules, chained)
	m.requirements[chained] = computeRequirements(chained.LHS)

	if _, err := m.ProcessEvent(epsilonTestEvent()); !errors.Is(err, ErrEpsilonDepth) || !strings.Contains(err.Error(), chained.Name) {
		t.Fatalf("ProcessEvent error = %v, want ErrEpsilonDepth naming %s", err, chained.Name)
	}
}

func TestNewMonitorChecksEpsilonRules(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	computation := term.NewFunction(epsilonTestFunction, []term.Term{x})
	emitted := func(event term.Term) []*rule.Fact {
		return []*rule.Fact{rule.NewFact(rule.RewriteEventName, []term.Term{event}, rule.LinearFact)}
	}
	consumeB := epsilonRule("EpsilonTestConsumeB", []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil, nil)

	tests := []struct {
		name    string
		rules   []*rule.Rule
		wantErr string
	}{
		{
			name: "epsilon conclusion",
			rules: []*rule.Rule{
				epsilonRule("EpsilonTestProduceB", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
				consumeB,
			},
			wantErr: "epsilon rule EpsilonTestConsumeB has premise EpsilonTestB, which epsilon rule EpsilonTestProduceB produces",
		},
		{
			name: "conclusion of a rule with a computation",
			rules: []*rule.Rule{
				triggerRule("EpsilonTestCompute", nil, []*rule.Fact{linearFact(epsilonTestFactB, computation)}, nil,
					term.NewFunction(term.PairFunctionName, []term.Term{computation, term.NewVariable("r")})),
				consumeB,
			},
			wantErr: "epsilon rule EpsilonTestConsumeB has premise EpsilonTestB, a conclusion of rule EpsilonTestCompute, " +
				"whose end rule produces it in an epsilon step in the split form",
		},
		{
			// Fusion makes the end rule of a nested computation consume the
			// event of the outer call. In the split form it is an epsilon
			// rule, as for a single computation.
			name: "conclusion of a fused end rule",
			rules: append(rule.Translate(&rule.Rule{
				Name:  "EpsilonTestNested",
				LHS:   []*rule.Fact{linearFact(epsilonTestFactA, x)},
				RHS:   []*rule.Fact{linearFact(epsilonTestFactB, term.NewFunction(epsilonTestFunction, []term.Term{computation}))},
				Attrs: map[string]rule.Attribute{},
			}), consumeB),
			wantErr: "epsilon rule EpsilonTestConsumeB has premise EpsilonTestB, a conclusion of rule EpsilonTestNested, " +
				"whose end rule produces it in an epsilon step in the split form",
		},
		{
			// A rule without premises keeps its start rule, a hint rule
			// that loading rejects, also with one innermost computation.
			name: "rule without premises",
			rules: rule.Translate(&rule.Rule{
				Name: "EpsilonTestNoPremise",
				RHS: []*rule.Fact{linearFact(epsilonTestFactB, term.NewFunction(epsilonTestFunction, []term.Term{
					term.NewFunction(epsilonTestFunction, []term.Term{term.NewConstant("1")}),
				}))},
				Attrs: map[string]rule.Attribute{},
			}),
			wantErr: "hint rule EpsilonTestNoPremise_Start has empty LHS",
		},
		{
			name: "epsilon producer named before a rule with a computation",
			rules: []*rule.Rule{
				triggerRule("EpsilonTestCompute", nil, []*rule.Fact{linearFact(epsilonTestFactB, computation)}, nil,
					term.NewFunction(term.PairFunctionName, []term.Term{computation, term.NewVariable("r")})),
				epsilonRule("EpsilonTestProduceB", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
				consumeB,
			},
			wantErr: "epsilon rule EpsilonTestConsumeB has premise EpsilonTestB, which epsilon rule EpsilonTestProduceB produces",
		},
		{
			name: "computation in an emitted event",
			rules: []*rule.Rule{
				triggerRule("EpsilonTestEmit", nil, []*rule.Fact{linearFact(epsilonTestFactB, x)},
					emitted(eventTerm(epsilonTestEventName, computation)), eventTerm(epsilonTestEventName, x)),
				consumeB,
			},
			wantErr: "a conclusion of rule EpsilonTestEmit, whose end rule produces it in an epsilon step in the split form",
		},
		{
			name: "split-state name produced by an epsilon rule",
			rules: []*rule.Rule{
				epsilonRule("EpsilonTestProduceState", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact("ST_EpsilonTest_0", x)}, nil),
				epsilonRule("EpsilonTest_End", []*rule.Fact{linearFact("ST_EpsilonTest_0", x)}, nil, nil),
			},
			wantErr: "epsilon rule EpsilonTest_End has premise ST_EpsilonTest_0, which epsilon rule EpsilonTestProduceState produces",
		},
		{
			name: "conclusion of a rule without a computation",
			rules: []*rule.Rule{
				epsilonTestTrigger(epsilonTestTriggerName, linearFact(epsilonTestFactB, term.NewConstant("1"))),
				consumeB,
			},
		},
		{
			// Only an end rule generated by the translation consumes
			// split-state facts. The name alone does not make one.
			name: "triggered rule named like an end rule",
			rules: []*rule.Rule{
				epsilonTestTrigger("EpsilonTestSource_End", linearFact(epsilonTestFactB, term.NewConstant("1"))),
				consumeB,
			},
		},
		{
			name: "emitted event call",
			rules: []*rule.Rule{
				triggerRule("EpsilonTestEmitCall", nil, []*rule.Fact{linearFact(epsilonTestFactB, x)},
					slices.Concat(
						emitted(term.NewFunction(term.PairFunctionName, []term.Term{computation, term.NewFunction(term.PairFunctionName, nil)})),
						emitted(computation)),
					eventTerm(epsilonTestEventName, x)),
				consumeB,
			},
		},
		{
			name: "persistent premise only",
			rules: []*rule.Rule{
				epsilonRule("EpsilonTestPersistent", []*rule.Fact{persistentP(x)}, nil, nil),
			},
			wantErr: "epsilon rule EpsilonTestPersistent has no linear premise",
		},
		{
			name: "empty premise",
			rules: []*rule.Rule{
				epsilonRule("EpsilonTestEmpty", nil, []*rule.Fact{linearFact(epsilonTestFactB, term.NewConstant("1"))}, nil),
			},
			wantErr: "epsilon rule EpsilonTestEmpty has no linear premise",
		},
		{
			name: "premise with another arity",
			rules: []*rule.Rule{
				epsilonRule("EpsilonTestProduceB", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestFactB, x)}, nil),
				epsilonRule("EpsilonTestConsumeB2", []*rule.Fact{linearFact(epsilonTestFactB, x, term.NewVariable("y"))}, nil, nil),
			},
		},
		{
			// Only the end rule of a decomposed rule consumes split state
			// without an epsilon step producing it.
			name: "fact named like split state",
			rules: []*rule.Rule{
				epsilonRule("EpsilonTestProduceState", []*rule.Fact{linearFact(epsilonTestFactA, x)}, []*rule.Fact{linearFact(epsilonTestState, x)}, nil),
				epsilonRule("EpsilonTestConsumeState", []*rule.Fact{linearFact(epsilonTestState, x)}, nil, nil),
			},
			wantErr: "epsilon rule EpsilonTestConsumeState has premise " + epsilonTestState + ", which epsilon rule EpsilonTestProduceState produces",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewMonitor(test.rules)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("NewMonitor: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("NewMonitor error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

// TestNewMonitorAcceptsSplitRules checks that the split-state facts which
// the end rule of a decomposed rule consumes do not count as produced. The
// rule has two leaves and two root children, so the translation keeps the
// start rule and an epsilon end rule.
func TestNewMonitorAcceptsSplitRules(t *testing.T) {
	t.Parallel()

	k := term.NewVariable("k")
	j := term.NewVariable("j")
	nested := func(x term.Term) term.Term {
		return term.NewFunction(epsilonTestFunction, []term.Term{term.NewFunction(epsilonTestFunction, []term.Term{x})})
	}
	source := &rule.Rule{
		Name:  "EpsilonTestSplit",
		LHS:   []*rule.Fact{linearFact(epsilonTestFactA, k), linearFact(epsilonTestFactC, j)},
		RHS:   []*rule.Fact{linearFact(epsilonTestFactB, nested(k)), linearFact(epsilonTestFactD, nested(j))},
		Attrs: map[string]rule.Attribute{},
	}
	split := rule.Translate(source)
	epsilons := slices.DeleteFunc(slices.Clone(split), func(r *rule.Rule) bool { return !r.IsEpsilon() })
	if len(epsilons) != 1 || !slices.ContainsFunc(epsilons[0].LHS, isSplitStateFact) {
		t.Fatalf("split rules %v, want one epsilon end rule over split-state facts", split)
	}
	if _, err := NewMonitor(split); err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
}

// isSplitStateFact reports whether f passes state between the split rules
// of one decomposed rule.
func isSplitStateFact(f *rule.Fact) bool {
	return strings.HasPrefix(f.Name, rule.SubtermName+rule.ComponentSep)
}

func TestEpsilonRewriteKindIdentity(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	input := eventTerm("epsilonIdentityInput", unit)
	fact := rule.NewFact("Ready", nil, rule.LinearFact)
	output := func(v term.Term) []*rule.Fact {
		pair := term.NewFunction(term.PairFunctionName, []term.Term{term.NewFunction("epsilonIdentityOutput", []term.Term{v}), unit})
		return []*rule.Fact{rule.NewFact(rule.RewriteEventName, []term.Term{pair}, rule.LinearFact)}
	}
	for _, tc := range []struct {
		name string
		a, b term.Term
		want int
	}{
		{"string_bytes", term.NewConstant("a"), term.NewConstant([]byte("a")), 2},
		{"integer_bytes", term.NewConstant(int64(97)), term.NewConstant([]byte{97, 0, 0, 0, 0, 0, 0, 0}), 2},
		{"nested_string_bytes", term.NewFunction(term.PairFunctionName, []term.Term{term.NewConstant("a"), unit}), term.NewFunction(term.PairFunctionName, []term.Term{term.NewConstant([]byte("a")), unit}), 2},
		{"identical_output", term.NewConstant("a"), term.NewConstant("a"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewMonitor([]*rule.Rule{
				triggerRule("Start", nil, []*rule.Fact{fact}, nil, input),
				epsilonRule("Text", []*rule.Fact{fact}, nil, output(tc.a)),
				epsilonRule("Bytes", []*rule.Fact{fact}, nil, output(tc.b)),
			})
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			apps, err := m.processEvent(input)
			if err != nil {
				t.Fatalf("process: %v", err)
			}
			t.Logf("applications=%d, configs=%d", len(apps), len(m.Configs()))
			if len(apps) != tc.want {
				t.Errorf("got %d applications, want %d", len(apps), tc.want)
			}
			_, err = rewriteOutputSequence(input, apps)
			if tc.want == 2 && !errors.Is(err, ErrNondeterministicRewrite) {
				t.Errorf("standalone error=%v, want ErrNondeterministicRewrite", err)
			}
			if tc.want == 1 && err != nil {
				t.Errorf("identical output: %v", err)
			}
		})
	}
}

func TestEpsilonActionsKeepFactKinds(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	ready := rule.NewFact("KindReady", nil, rule.LinearFact)
	m, err := NewMonitor([]*rule.Rule{
		triggerRule("KindStart", nil, []*rule.Fact{ready}, nil, eventTerm("kindStart", unit)),
		epsilonRule("KindLinear", []*rule.Fact{ready}, nil, []*rule.Fact{rule.NewFact("Observe", []term.Term{unit}, rule.LinearFact)}),
		epsilonRule("KindPersistent", []*rule.Fact{ready}, nil, []*rule.Fact{rule.NewFact("Observe", []term.Term{unit}, rule.PersistentFact)}),
	})
	if err != nil {
		t.Fatal(err)
	}
	apps, err := m.processEvent(eventTerm("kindStart", unit))
	if err != nil || len(apps) != 2 {
		t.Fatalf("applications = %d, error = %v; want two", len(apps), err)
	}
}
