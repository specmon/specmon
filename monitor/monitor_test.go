// Copyright (C) 2025-2026 CISPA Helmholtz Center for Information Security
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

package monitor_test

import (
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// TestMonitorHintTriggerActionsBothSurvive verifies that action
// forwarding is per rule application, not per resulting config.
// handleHints wraps each downstream trigger's outcome as
// RuleApplication{hint rule, hint binding, trigger config, hint
// actions + trigger actions}. When two downstream triggers (T1, T2)
// match the same event with the same binding and land on the same
// final config, only the action payload differs, so any dedup of
// applications short of their full action lists would drop one of
// them. Applications are therefore collected as a plain slice and
// only configs are deduplicated.
func TestMonitorHintTriggerActionsBothSurvive(t *testing.T) {
	// Hint H: matches event <go, x>. Consumes Init(), produces State(x),
	// emits PPEvent(hintOut(x)). The Init() fact gets installed by an
	// initial trigger event (see below).
	hintRule := &rule.Rule{
		Name: "H",
		LHS: []*rule.Fact{
			rule.NewFact("Init", []term.Term{}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("x")}, rule.LinearFact),
		},
		Act: []*rule.Fact{
			rule.NewFact(rule.RewriteEventName, []term.Term{
				emittedEvent(term.NewFunction("hintOut", []term.Term{term.NewVariable("x")})),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"hint": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("go", []term.Term{}),
						term.NewVariable("x"),
					}),
				},
			},
		},
	}

	// Setup rule that installs Init() in response to <setup, ()>.
	setupRule := &rule.Rule{
		Name: "Setup",
		LHS:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("Init", []term.Term{}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("setup", []term.Term{}),
						term.NewFunction("pair", []term.Term{}),
					}),
				},
			},
		},
	}

	// Trigger T1: matches event <go, x>. LHS State(x), produces nothing, emits PPEvent(t1(x)).
	t1Rule := &rule.Rule{
		Name: "T1",
		LHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("x")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{},
		Act: []*rule.Fact{
			rule.NewFact(rule.RewriteEventName, []term.Term{
				emittedEvent(term.NewFunction("t1", []term.Term{term.NewVariable("x")})),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("go", []term.Term{}),
						term.NewVariable("x"),
					}),
				},
			},
		},
	}

	// Trigger T2: same shape as T1, different action.
	t2Rule := &rule.Rule{
		Name: "T2",
		LHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("x")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{},
		Act: []*rule.Fact{
			rule.NewFact(rule.RewriteEventName, []term.Term{
				emittedEvent(term.NewFunction("t2", []term.Term{term.NewVariable("x")})),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("go", []term.Term{}),
						term.NewVariable("x"),
					}),
				},
			},
		},
	}

	mon, err := monitor.NewMonitor([]*rule.Rule{setupRule, hintRule, t1Rule, t2Rule})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}

	// Setup event to install Init().
	setupEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("setup", []term.Term{}),
		term.NewFunction("pair", []term.Term{}),
	})
	if _, err := mon.ProcessEvent(setupEvent); err != nil {
		t.Fatalf("ProcessEvent(setup): %v", err)
	}

	// The hint-trigger event.
	event := term.NewFunction("pair", []term.Term{
		term.NewFunction("go", []term.Term{}),
		term.NewConstant("42"),
	})

	actions, err := mon.ProcessEvent(event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}

	// Flatten the per-application action groups for inspection.
	var flat []*rule.Fact
	for _, group := range actions {
		flat = append(flat, group...)
	}

	// We expect the rewrite output to include BOTH t1 and t2 PPEvents.
	// The hint's PPEvent appears once per path (twice total) since it
	// is prepended into each downstream application's action list.
	var sawT1, sawT2 bool
	hintCount := 0
	for _, f := range flat {
		if f.Name != rule.RewriteEventName || len(f.Args) != 1 {
			continue
		}
		fn, ok := emittedCall(f.Args[0])
		if !ok {
			continue
		}
		switch fn.Name {
		case "t1":
			sawT1 = true
		case "t2":
			sawT2 = true
		case "hintOut":
			hintCount++
		}
	}

	if !sawT1 {
		t.Errorf("t1 PPEvent missing from rewrite output: %v", flat)
	}
	if !sawT2 {
		t.Errorf("t2 PPEvent missing from rewrite output: %v — did application dedup collapse distinct-action applications?", flat)
	}
	if hintCount < 2 {
		t.Errorf("hintOut PPEvent should appear once per downstream trigger (2 total), got %d", hintCount)
	}
}

// TestMonitorHintTriggerEmptyActionsBothSurvive strengthens
// TestMonitorHintTriggerActionsBothSurvive: T1 and T2 have EMPTY Act
// lists and land on the same final config, so the two wrapped hint
// applications are indistinguishable by (rule, binding, config,
// actions). ANY set-based dedup of RuleApplication would collapse
// them; the slice-based collection keeps both, so the hint action
// must appear once per downstream trigger path.
func TestMonitorHintTriggerEmptyActionsBothSurvive(t *testing.T) {
	hintRule := &rule.Rule{
		Name: "H",
		LHS: []*rule.Fact{
			rule.NewFact("Init", []term.Term{}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("x")}, rule.LinearFact),
		},
		Act: []*rule.Fact{
			rule.NewFact(rule.RewriteEventName, []term.Term{
				emittedEvent(term.NewFunction("hintOut", []term.Term{term.NewVariable("x")})),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"hint": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("go", []term.Term{}),
						term.NewVariable("x"),
					}),
				},
			},
		},
	}

	setupRule := &rule.Rule{
		Name: "Setup",
		LHS:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("Init", []term.Term{}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("setup", []term.Term{}),
						term.NewFunction("pair", []term.Term{}),
					}),
				},
			},
		},
	}

	// T1 and T2 both consume State(x), produce nothing, emit NO Acts.
	// Identical externally-visible result (same final config, same
	// action list) but distinct rule pointers.
	makeTrigger := func(name string) *rule.Rule {
		return &rule.Rule{
			Name: name,
			LHS: []*rule.Fact{
				rule.NewFact("State", []term.Term{term.NewVariable("x")}, rule.LinearFact),
			},
			RHS: []*rule.Fact{},
			Act: nil,
			Attrs: map[string]rule.Attribute{
				"trigger": rule.TermAttribute{
					Value: []term.Term{
						term.NewFunction("pair", []term.Term{
							term.NewFunction("go", []term.Term{}),
							term.NewVariable("x"),
						}),
					},
				},
			},
		}
	}
	t1Rule := makeTrigger("T1")
	t2Rule := makeTrigger("T2")

	mon, err := monitor.NewMonitor([]*rule.Rule{setupRule, hintRule, t1Rule, t2Rule})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}

	setupEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("setup", []term.Term{}),
		term.NewFunction("pair", []term.Term{}),
	})
	if _, err := mon.ProcessEvent(setupEvent); err != nil {
		t.Fatalf("ProcessEvent(setup): %v", err)
	}

	event := term.NewFunction("pair", []term.Term{
		term.NewFunction("go", []term.Term{}),
		term.NewConstant("42"),
	})

	actions, err := mon.ProcessEvent(event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}

	// Count hintOut PPEvents in the flattened action stream.
	hintCount := 0
	for _, group := range actions {
		for _, f := range group {
			if f.Name != rule.RewriteEventName || len(f.Args) != 1 {
				continue
			}
			fn, ok := emittedCall(f.Args[0])
			if !ok {
				continue
			}
			if fn.Name == "hintOut" {
				hintCount++
			}
		}
	}

	if hintCount != 2 {
		t.Errorf("hintOut PPEvent should appear once per downstream trigger path "+
			"(2 expected even with empty trigger Acts and identical final configs), got %d. "+
			"Did RuleApplication dedup collapse distinct hint-trigger paths?", hintCount)
	}
}

// TestMonitorMultipleFrFacts tests a bug in conflictSet with a
// rule with two Fr facts, and we test the internal rule matching logic.
func TestMonitorMultipleFrFacts(t *testing.T) {
	// Create a simple rule that consumes two Fr facts with a pseudo trigger
	testRule := &rule.Rule{
		Name: "TwoFr",
		LHS: []*rule.Fact{
			rule.NewFact("Fr", []term.Term{term.NewVariable("x")}, rule.LinearFact),
			rule.NewFact("Fr", []term.Term{term.NewVariable("y")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("x"), term.NewVariable("y")}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("test", []term.Term{}),
						term.NewFunction("pair", []term.Term{}),
					}),
				},
			},
		},
	}

	// Create monitor with this rule
	mon, err := monitor.NewMonitor([]*rule.Rule{testRule})
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	// Get the initial config and add two Fr facts with different values
	configs := mon.Configs()
	if len(configs) != 1 {
		t.Fatalf("Expected 1 initial config, got %d", len(configs))
	}
	config := configs[0]

	// Add two Fr facts with different values
	// The conflictSet bug should affect how these are matched by the rule
	config.AddFact(rule.NewFact("Fr", []term.Term{term.NewConstant("alice")}, rule.LinearFact))
	config.AddFact(rule.NewFact("Fr", []term.Term{term.NewConstant("bob")}, rule.LinearFact))

	// Verify we have 2 facts
	if len(config.Facts()) != 2 {
		t.Fatalf("Expected 2 facts, got %d", len(config.Facts()))
	}

	// Process the test event that matches our pseudo trigger
	testEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("test", []term.Term{}),
		term.NewFunction("pair", []term.Term{}),
	})

	_, err = mon.ProcessEvent(testEvent)
	if err != nil {
		t.Fatalf("ProcessEvent failed: %v", err)
	}

	// Check the resulting configurations
	// The broken conflictSet should cause different behavior in rule matching
	resultConfigs := mon.Configs()
	if len(resultConfigs) == 0 {
		t.Errorf("Expected some configurations after processing event")
	}

	t.Logf("Processed event successfully, got %d result configs", len(resultConfigs))
}

// TestMonitorEpsilonActionsForwarded verifies that epsilon-rule
// actions are forwarded: when an epsilon rule fires after a trigger
// rule and emits a PPEvent action, ProcessEvent's returned action
// groups must include the epsilon's actions, not just the trigger's.
//
// Setup:
//   - Trigger rule "Go" consumes event <go, ret> and produces State(ret).
//     Its Act emits PPEvent(triggered(ret)).
//   - Epsilon rule "Promote" consumes State(x) (no trigger/hint) and
//     emits Act PPEvent(promoted(x)).
//
// On a single ProcessEvent(<go, 42>), both PPEvents must appear in the
// returned actions: handleEpsilon returns the epsilon's Act facts and
// handleTriggers concatenates them onto the trigger's.
func TestMonitorEpsilonActionsForwarded(t *testing.T) {
	goTrigger := &rule.Rule{
		Name: "Go",
		LHS:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("ret")}, rule.LinearFact),
		},
		Act: []*rule.Fact{
			rule.NewFact(rule.RewriteEventName, []term.Term{
				emittedEvent(term.NewFunction("triggered", []term.Term{term.NewVariable("ret")})),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("go", []term.Term{}),
						term.NewVariable("ret"),
					}),
				},
			},
		},
	}

	promote := &rule.Rule{
		Name: "Promote",
		LHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("x")}, rule.LinearFact),
		},
		// No RHS, no trigger, no hint -> epsilon rule.
		Act: []*rule.Fact{
			rule.NewFact(rule.RewriteEventName, []term.Term{
				emittedEvent(term.NewFunction("promoted", []term.Term{term.NewVariable("x")})),
			}, rule.LinearFact),
		},
		// Empty (but non-nil) Attrs so Rule.Subst can populate the
		// trigger/hint slots without panicking on nil map writes. Real
		// parsed epsilon rules carry this empty map already.
		Attrs: map[string]rule.Attribute{},
	}

	mon, err := monitor.NewMonitor([]*rule.Rule{goTrigger, promote})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}

	event := term.NewFunction("pair", []term.Term{
		term.NewFunction("go", []term.Term{}),
		term.NewConstant("42"),
	})

	actions, err := mon.ProcessEvent(event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}

	// Flatten into a single slice for inspection. There should be at
	// least one group, and its contents must include BOTH PPEvents.
	var flat []*rule.Fact
	for _, group := range actions {
		flat = append(flat, group...)
	}

	if len(flat) < 2 {
		t.Fatalf("expected at least 2 action facts (trigger + epsilon PPEvents), got %d: %v", len(flat), flat)
	}

	var sawTriggered, sawPromoted bool
	for _, f := range flat {
		if f.Name != rule.RewriteEventName || len(f.Args) != 1 {
			continue
		}
		fn, ok := emittedCall(f.Args[0])
		if !ok {
			continue
		}
		switch fn.Name {
		case "triggered":
			sawTriggered = true
		case "promoted":
			sawPromoted = true
		}
	}

	if !sawTriggered {
		t.Errorf("trigger PPEvent(triggered(...)) missing from actions: %v", flat)
	}
	if !sawPromoted {
		t.Errorf("epsilon PPEvent(promoted(...)) missing from actions: %v — epsilon actions dropped?", flat)
	}
}

// TestMonitorRestrictionViolation tests that when multiple rules can match an event
// but one fails due to a restriction violation (e.g., Eq check), the monitor continues
// to try other rules instead of returning an error immediately.
func TestMonitorRestrictionViolation(t *testing.T) {
	// Create an In rule that adds In(x) to state
	inRule := &rule.Rule{
		Name: "In",
		LHS:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("In", []term.Term{term.NewVariable("x")}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("in", []term.Term{}),
						term.NewVariable("x"),
					}),
				},
			},
		},
	}

	// Create rule A: consumes In($x) with restriction Eq($x, '1')
	ruleA := &rule.Rule{
		Name: "A",
		LHS: []*rule.Fact{
			rule.NewFact("In", []term.Term{term.NewVariable("$x")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("A", []term.Term{
				term.NewFunction("h", []term.Term{term.NewVariable("$x")}),
			}, rule.LinearFact),
		},
		Act: []*rule.Fact{
			rule.NewFact("Eq", []term.Term{
				term.NewVariable("$x"),
				term.NewConstant("1"),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("h", []term.Term{term.NewVariable("$x")}),
						term.NewVariable("h$x"),
					}),
				},
			},
		},
	}

	// Create rule B: consumes In($x) with restriction Eq($x, '2')
	ruleB := &rule.Rule{
		Name: "B",
		LHS: []*rule.Fact{
			rule.NewFact("In", []term.Term{term.NewVariable("$x")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("B", []term.Term{
				term.NewFunction("h", []term.Term{term.NewVariable("$x")}),
			}, rule.LinearFact),
		},
		Act: []*rule.Fact{
			rule.NewFact("Eq", []term.Term{
				term.NewVariable("$x"),
				term.NewConstant("2"),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("h", []term.Term{term.NewVariable("$x")}),
						term.NewVariable("h$x"),
					}),
				},
			},
		},
	}

	// Create monitor with all three rules
	mon, err := monitor.NewMonitor([]*rule.Rule{inRule, ruleA, ruleB})
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	// Process first event: <in(), 1>
	inEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("in", []term.Term{}),
		term.NewConstant("1"),
	})

	_, err = mon.ProcessEvent(inEvent)
	if err != nil {
		t.Fatalf("ProcessEvent failed for in event: %v", err)
	}

	// Process second event: <h(1), 42>
	hEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("h", []term.Term{term.NewConstant("1")}),
		term.NewConstant("42"),
	})

	_, err = mon.ProcessEvent(hEvent)
	if err != nil {
		t.Fatalf("ProcessEvent failed for h event: %v", err)
	}

	// Check the resulting configurations
	resultConfigs := mon.Configs()
	if len(resultConfigs) != 1 {
		t.Fatalf("Expected 1 configuration, got %d", len(resultConfigs))
	}

	// Verify that rule A was applied (fact A exists) and rule B was not (fact B doesn't exist)
	config := resultConfigs[0]
	facts := config.Facts()

	foundA := false
	foundB := false
	for _, fact := range facts {
		if fact.Name == "A" {
			foundA = true
		}
		if fact.Name == "B" {
			foundB = true
		}
	}

	if !foundA {
		t.Errorf("Expected fact A to exist (rule A should have succeeded)")
	}
	if foundB {
		t.Errorf("Expected fact B to not exist (rule B should have failed due to restriction)")
	}

	t.Logf("Test passed: Rule A succeeded, Rule B failed due to restriction violation")
}

// TestMonitorTriggerAnchoredToCurrentEvent pins the trigger anchoring
// semantics: every rule application performed while processing event a
// must consume an instance of a itself. Earlier trigger events exist only
// in hidden pending applications and cannot fill the current trigger slot.
//
// Scenario: R1 starts on go events, but its done trigger never arrives. R2
// consumes Gate() on <go, x>, where x occurs only in the trigger. The
// trace starts R1 on <go,'1'> while R2 is inapplicable, creates Gate(),
// then sends <go,'2'>.
//
// Exactly two public configurations must result:
//
//	{ [Gate()] }      (R1 also starts on <go,'2'>)
//	{ [State('2')] }  (R2 fires on <go,'2'>)
//
// A configuration containing State('1') is invalid and must be unreachable.
// Neither configuration exposes the earlier events through Config.String.
func TestMonitorTriggerAnchoredToCurrentEvent(t *testing.T) {
	pairEv := func(name string, arg term.Term) *term.Function {
		return term.NewFunction("pair", []term.Term{
			term.NewFunction(name, []term.Term{}), arg,
		})
	}

	r1 := &rule.Rule{
		Name: "R1", LHS: []*rule.Fact{}, RHS: []*rule.Fact{},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{Value: []term.Term{
				pairEv("go", term.NewVariable("y")),
				pairEv("done", term.NewVariable("y")),
			}},
		},
	}
	r2 := &rule.Rule{
		Name: "R2",
		LHS:  []*rule.Fact{rule.NewFact("Gate", []term.Term{}, rule.LinearFact)},
		RHS:  []*rule.Fact{rule.NewFact("State", []term.Term{term.NewVariable("x")}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{Value: []term.Term{
				pairEv("go", term.NewVariable("x")),
			}},
		},
	}
	r3 := &rule.Rule{
		Name: "R3", LHS: []*rule.Fact{},
		RHS: []*rule.Fact{rule.NewFact("Gate", []term.Term{}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{Value: []term.Term{
				pairEv("mk", term.NewVariable("z")),
			}},
		},
	}

	mon, err := monitor.NewMonitor([]*rule.Rule{r1, r2, r3})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	step := func(name, val string) {
		if _, err := mon.ProcessEvent(pairEv(name, term.NewConstant(val))); err != nil {
			t.Fatalf("ProcessEvent(%s,%s): %v", name, val, err)
		}
	}

	step("go", "1")
	step("mk", "0")
	step("go", "2")

	configs := mon.Configs()
	if len(configs) != 2 {
		for i, c := range configs {
			t.Logf("config %d: %s", i, c)
		}
		t.Fatalf("expected exactly 2 configurations, got %d", len(configs))
	}

	var sawFired, sawPending bool
	for _, c := range configs {
		s := c.String()
		if strings.Contains(s, "State('1')") {
			t.Errorf("invalid configuration reached: R2 bound its trigger from the earlier <go,'1'>: %s", s)
		}
		if strings.Contains(s, "<go()") {
			t.Errorf("configuration exposed a completed trigger event: %s", s)
		}
		switch {
		case strings.Contains(s, "State('2')"):
			sawFired = true
		case strings.Contains(s, "Gate()"):
			sawPending = true
		}
	}
	if !sawFired {
		t.Errorf("missing public configuration { [State('2')] }")
	}
	if !sawPending {
		t.Errorf("missing public configuration { [Gate()] }")
	}
}

func TestProcessEventHandlesInvalidEvaluatedCandidates(t *testing.T) {
	t.Parallel()

	const (
		eventFunctionName = "evaluationEvent"
		setupFunctionName = "evaluationSetup"
		stateFactName     = "EvaluationState"
		invalidRuleName   = "InvalidCandidate"
		validRuleName     = "ValidCandidate"
		setupRuleName     = "EvaluationSetup"
	)

	pairEvent := func(name string, value term.Term) term.Term {
		return term.NewFunction(term.PairFunctionName, []term.Term{
			term.NewFunction(name, nil),
			value,
		})
	}
	invalidArgument := term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant[int64](math.MaxInt64), term.NewConstant[int64](1)})
	invalidCandidate := pairEvent(eventFunctionName, invalidArgument)
	validCandidate := pairEvent(eventFunctionName, term.NewVariable("value"))
	event := pairEvent(eventFunctionName, term.NewConstant[int64](2))
	setupEvent := pairEvent(setupFunctionName, term.NewFunction(term.PairFunctionName, nil))

	for _, attributeName := range []string{rule.TriggerAttributeName, rule.HintAttributeName} {
		t.Run(attributeName, func(t *testing.T) {
			setupRule := &rule.Rule{
				Name: setupRuleName,
				RHS:  []*rule.Fact{rule.NewFact(stateFactName, nil, rule.LinearFact)},
				Attrs: map[string]rule.Attribute{
					rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{setupEvent}},
				},
			}
			invalidRule := &rule.Rule{
				Name: invalidRuleName,
				LHS:  []*rule.Fact{rule.NewFact(stateFactName, nil, rule.LinearFact)},
				Attrs: map[string]rule.Attribute{
					attributeName: rule.TermAttribute{Value: []term.Term{invalidCandidate}},
				},
			}
			validRule := &rule.Rule{
				Name: validRuleName,
				LHS:  []*rule.Fact{rule.NewFact(stateFactName, nil, rule.LinearFact)},
				Attrs: map[string]rule.Attribute{
					rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{validCandidate}},
				},
			}

			for _, test := range []struct {
				name      string
				withValid bool
			}{
				{name: "valid candidate", withValid: true},
				{name: "no valid candidate"},
			} {
				t.Run(test.name, func(t *testing.T) {
					rules := []*rule.Rule{setupRule, invalidRule}
					if test.withValid {
						rules = append(rules, validRule)
					}

					mon, err := monitor.NewMonitor(rules)
					if err != nil {
						t.Fatalf("NewMonitor: %v", err)
					}
					if _, err := mon.ProcessEvent(setupEvent); err != nil {
						t.Fatalf("ProcessEvent setup: %v", err)
					}

					_, err = mon.ProcessEvent(event)
					if test.withValid {
						if err != nil {
							t.Fatalf("ProcessEvent rejected a valid candidate after an invalid one: %v", err)
						}
						return
					}
					// A failed evaluation is not a match. With no other
					// candidate the event is rejected.
					if !errors.Is(err, monitor.ErrNoApplicableRule) || errors.Is(err, term.ErrEvaluation) {
						t.Fatalf("ProcessEvent error = %v, want ErrNoApplicableRule", err)
					}
				})
			}
		})
	}
}

func TestProcessEventReturnsEpsilonEvaluationErrors(t *testing.T) {
	t.Parallel()

	const (
		eventFunctionName = "epsilonEvaluationEvent"
		triggerRuleName   = "TriggerEpsilonEvaluation"
		epsilonRuleName   = "InvalidEpsilonEvaluation"
		invalidFactName   = "InvalidEpsilonResult"
		readyFactName     = "EpsilonEvaluationReady"
	)

	event := term.NewFunction(term.PairFunctionName, []term.Term{
		term.NewFunction(eventFunctionName, nil),
		term.NewFunction(term.PairFunctionName, nil),
	})
	triggerRule := &rule.Rule{
		Name: triggerRuleName,
		RHS:  []*rule.Fact{rule.NewFact(readyFactName, nil, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{event}},
		},
	}
	invalid := term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant[int64](math.MaxInt64), term.NewConstant[int64](1)})
	epsilonRule := &rule.Rule{
		Name: epsilonRuleName,
		LHS:  []*rule.Fact{rule.NewFact(readyFactName, nil, rule.LinearFact)},
		RHS: []*rule.Fact{
			rule.NewFact(invalidFactName, []term.Term{invalid}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{},
	}

	mon, err := monitor.NewMonitor([]*rule.Rule{triggerRule, epsilonRule})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	_, err = mon.ProcessEvent(event)
	if !errors.Is(err, term.ErrEvaluation) {
		t.Fatalf("ProcessEvent error = %v, want ErrEvaluation", err)
	}
	for _, config := range mon.Configs() {
		if config.CountByName(invalidFactName) != 0 {
			t.Fatalf("ProcessEvent published an invalid epsilon result: %v", config.Facts())
		}
	}
}

// TestRuleConclusionKeepsUnobservedCallsSymbolic checks that a rule whose
// conclusion concatenates calls that are neither evaluable nor observed
// applies and stores the concatenation symbolically.
func TestRuleConclusionKeepsUnobservedCallsSymbolic(t *testing.T) {
	x := term.NewVariable("x")
	r := term.NewVariable("r")
	call := func(name string, args ...term.Term) *term.Function { return term.NewFunction(name, args) }
	field := func(value term.Term) term.Term { return call(string(term.FormatByteType), value) }
	concatenation := call(term.CatFunctionName, field(call("symbolicF", x)), field(call("symbolicG", x)))
	build := &rule.Rule{
		Name: "BuildSymbolic",
		RHS:  []*rule.Fact{rule.NewFact("SymbolicOut", []term.Term{concatenation}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{call(term.PairFunctionName, call("symbolicGo", x), r)}},
		},
	}
	m, err := monitor.NewMonitor([]*rule.Rule{build})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	value := term.NewConstant([]byte{1})
	if _, err := m.ProcessEvent(call(term.PairFunctionName, call("symbolicGo", value), call(term.PairFunctionName))); err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	binding := term.NewBinding()
	binding.Set(x, value)
	want := rule.NewFact("SymbolicOut", []term.Term{concatenation.Subst(binding)}, rule.LinearFact)
	configs := m.Configs()
	if len(configs) != 1 || !slices.ContainsFunc(configs[0].Facts(), want.Equal) {
		t.Fatalf("configurations = %v, want one with %s", configs, want)
	}
}

// TestFinalIntFieldWithoutWidthTakesEightBytes checks that a trigger and a
// premise whose last field is an int without a width match only eight bytes
// there, the width with which the matched instance is rebuilt.
func TestFinalIntFieldWithoutWidthTakesEightBytes(t *testing.T) {
	t.Parallel()

	call := func(name string, args ...term.Term) *term.Function { return term.NewFunction(name, args) }
	event := func(name string, result term.Term) *term.Function {
		return call(term.PairFunctionName, call(name), result)
	}
	triggered := func(r *rule.Rule, trigger *term.Function) *rule.Rule {
		r.Attrs = map[string]rule.Attribute{rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{trigger}}}
		return r
	}
	x, a := term.NewVariable("x"), term.NewVariable("a")
	pattern := call(term.CatFunctionName,
		call(string(term.FormatByteType), x, term.NewConstant[int64](1)),
		call(string(term.FormatIntType), a))
	empty := call(term.PairFunctionName)
	for _, test := range []struct {
		name    string
		value   []byte
		wantErr error
	}{
		{"eight bytes", []byte{1, 5, 0, 0, 0, 0, 0, 0, 0}, nil},
		{"one byte", []byte{1, 5}, monitor.ErrNoApplicableRule},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := term.NewConstant(test.value)
			rules := []*rule.Rule{
				triggered(&rule.Rule{Name: "ParseTrigger", RHS: []*rule.Fact{rule.NewFact("Parsed", []term.Term{a}, rule.LinearFact)}},
					event("finalIntInput", pattern)),
				triggered(&rule.Rule{Name: "Store", RHS: []*rule.Fact{rule.NewFact("Stored", []term.Term{value}, rule.LinearFact)}},
					event("finalIntStore", empty)),
				triggered(&rule.Rule{
					Name: "ParsePremise",
					LHS:  []*rule.Fact{rule.NewFact("Stored", []term.Term{pattern}, rule.LinearFact)},
					RHS:  []*rule.Fact{rule.NewFact("Parsed", []term.Term{a}, rule.LinearFact)},
				}, event("finalIntUse", empty)),
			}
			for _, events := range [][]*term.Function{
				{event("finalIntInput", value)},
				{event("finalIntStore", empty), event("finalIntUse", empty)},
			} {
				m, err := monitor.NewMonitor(rules)
				if err != nil {
					t.Fatalf("NewMonitor: %v", err)
				}
				for _, e := range events[:len(events)-1] {
					if _, err := m.ProcessEvent(e); err != nil {
						t.Fatalf("ProcessEvent(%s): %v", e, err)
					}
				}
				last := events[len(events)-1]
				_, err = m.ProcessEvent(last)
				if test.wantErr != nil {
					if !errors.Is(err, test.wantErr) {
						t.Fatalf("ProcessEvent(%s) error = %v, want %v", last, err, test.wantErr)
					}
					continue
				}
				if configs := m.Configs(); err != nil || len(configs) != 1 || configs[0].CountByName("Parsed") != 1 {
					t.Fatalf("ProcessEvent(%s) = %v, configurations %v", last, err, configs)
				}
			}
		})
	}
}

// emittedEvent returns the rewrite output <call, <>>.
func emittedEvent(call *term.Function) term.Term {
	return term.NewFunction(term.PairFunctionName, []term.Term{call, term.NewFunction(term.PairFunctionName, nil)})
}

// emittedCall returns the event call of a rewrite output <call, result>.
func emittedCall(output term.Term) (*term.Function, bool) {
	pair, err := term.AsFunction(output)
	if err != nil || pair == nil || pair.Name != term.PairFunctionName || len(pair.Args) != 2 {
		return nil, false
	}
	call, err := term.AsFunction(pair.Args[0])
	return call, err == nil && call != nil
}
