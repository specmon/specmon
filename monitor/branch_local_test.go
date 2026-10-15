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
	"bytes"
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

const (
	branchTestEventName    = "branchTestGo"
	branchTestSetupName    = "branchTestSetup"
	branchTestFirstName    = "branchTestFirst"
	branchTestSecondName   = "branchTestSecond"
	branchTestOtherName    = "branchTestOther"
	branchTestOutputName   = "branchTestOutput"
	branchTestCallName     = "branchTestCall"
	branchTestFactA        = "BranchTestA"
	branchTestFactB        = "BranchTestB"
	branchTestFactC        = "BranchTestC"
	branchTestFactD        = "BranchTestD"
	branchTestFactP        = "BranchTestP"
	branchTestFactQ        = "BranchTestQ"
	branchTestReady        = "BranchTestReady"
	branchTestGood         = "BranchTestGood"
	branchTestBad          = "BranchTestBad"
	branchTestFinished     = "BranchTestFinished"
	branchTestDone         = "BranchTestDone"
	branchTestRuleFailing  = "BranchTestFailing"
	branchTestRuleSurvivor = "BranchTestSurvivor"
	branchTestRuleNative   = "BranchTestNative"
	branchTestRuleAfter    = "BranchTestAfter"
)

func branchTestEvent(name string) term.Term {
	return eventTerm(name, term.NewFunction(term.PairFunctionName, nil))
}

// branchTestOrders returns rules and its reverse, so that a failing and a
// surviving alternative are tried in both orders.
func branchTestOrders(rules ...*rule.Rule) map[string][]*rule.Rule {
	reversed := slices.Clone(rules)
	slices.Reverse(reversed)
	return map[string][]*rule.Rule{
		"failing first":   rules,
		"surviving first": reversed,
	}
}

// branchTestArrivals returns both arrival orders of the triggers of a
// native rule made by branchTestNative.
func branchTestArrivals() map[string][]term.Term {
	first, second := branchTestEvent(branchTestFirstName), branchTestEvent(branchTestSecondName)
	return map[string][]term.Term{"first then second": {first, second}, "second then first": {second, first}}
}

// runEvents creates a monitor with rules, adds facts to its initial
// configuration and processes events. Every event but the last must be
// accepted. The result of the last is returned.
func runEvents(t *testing.T, rules []*rule.Rule, facts []*rule.Fact, events ...term.Term) (*Monitor, [][]*rule.Fact, error) {
	t.Helper()
	m := newEpsilonTestMonitor(t, rules...)
	for _, fact := range facts {
		m.Configs()[0].AddFact(fact)
	}
	last := len(events) - 1
	for _, event := range events[:last] {
		if _, err := m.ProcessEvent(event); err != nil {
			t.Fatalf("ProcessEvent(%s): %v", event, err)
		}
	}
	actions, err := m.ProcessEvent(events[last])
	return m, actions, err
}

// wantActions checks the projection of the published actions.
func wantActions(t *testing.T, actions [][]*rule.Fact, want ...string) {
	t.Helper()
	if got := actionProjection(actions); !slices.Equal(got, want) {
		t.Errorf("actions = %q, want %q", got, want)
	}
}

// wantRejected checks that an event was rejected and that no
// configuration of m is live.
func wantRejected(t *testing.T, m *Monitor, err error) {
	t.Helper()
	if !errors.Is(err, ErrNoApplicableRule) {
		t.Fatalf("ProcessEvent error = %v, want ErrNoApplicableRule", err)
	}
	if configs := m.Configs(); len(configs) != 0 {
		t.Errorf("configurations = %v, want none", configs)
	}
}

// TestEpsilonDepthPrunesAcrossConfigurations checks that a branch pruned
// for depth in one configuration does not end the event for another
// configuration, in both orders of the configurations.
func TestEpsilonDepthPrunesAcrossConfigurations(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	one := term.NewConstant("1")
	toP := triggerRule("BranchTestToP", nil, []*rule.Fact{linearFact(branchTestFactP, one)}, nil, branchTestEvent(branchTestSetupName))
	toQ := triggerRule("BranchTestToQ", nil, []*rule.Fact{linearFact(branchTestFactQ, one)}, nil, branchTestEvent(branchTestSetupName))
	fromP := triggerRule("BranchTestFromP", []*rule.Fact{linearFact(branchTestFactP, x)},
		[]*rule.Fact{linearFact(branchTestFactA, x), linearFact(branchTestFactC, x)}, nil, branchTestEvent(branchTestEventName))
	fromQ := triggerRule("BranchTestFromQ", []*rule.Fact{linearFact(branchTestFactQ, x)},
		[]*rule.Fact{linearFact(branchTestGood, x)}, nil, branchTestEvent(branchTestEventName))
	epsilonA := epsilonRule("BranchTestEpsilonA", []*rule.Fact{linearFact(branchTestFactA, x)}, []*rule.Fact{linearFact(branchTestFactB, x)}, nil)
	epsilonC := epsilonRule("BranchTestEpsilonC", []*rule.Fact{linearFact(branchTestFactC, x)}, []*rule.Fact{linearFact(branchTestFactD, x)}, nil)

	for name, setup := range map[string][]*rule.Rule{
		"pruned configuration first": {toP, toQ},
		"pruned configuration last":  {toQ, toP},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, _ := acceptEvents(t, slices.Concat(setup, []*rule.Rule{fromP, fromQ, epsilonA, epsilonC}), nil,
				branchTestEvent(branchTestSetupName), branchTestEvent(branchTestEventName))
			wantConfigs(t, m, factProjection(linearFact(branchTestGood, one)))
			wantFailures(t, m, FailureCounts{EpsilonDepth: 2})
		})
	}
}

// branchTestNative returns a rule with the triggers first and second whose
// completion produces Finished and has the given actions, and an epsilon
// rule that consumes Finished, so that a completion is pruned for depth.
func branchTestNative(rhs, actions []*rule.Fact) []*rule.Rule {
	return []*rule.Rule{
		triggerRule(branchTestRuleNative, nil, rhs, actions,
			branchTestEvent(branchTestFirstName), branchTestEvent(branchTestSecondName)),
		epsilonRule(branchTestRuleAfter, []*rule.Fact{linearFact(branchTestFinished)}, []*rule.Fact{linearFact(branchTestDone)}, nil),
	}
}

// TestNativeCompletionFailuresAreLocal checks that a completion of a native
// multi-trigger application that fails its restriction or evaluation or is
// pruned for depth ends only its branch, for both arrival orders of the
// triggers. Beside a rule that consumes the completing event in the same
// configuration, the survivor keeps the pending application started by the
// first event, and the start that the completion's match suppressed is not
// restored. Alone, the event is rejected.
func TestNativeCompletionFailuresAreLocal(t *testing.T) {
	t.Parallel()

	ready := linearFact(branchTestReady)
	for _, test := range []struct {
		name         string
		rhs, actions []*rule.Fact
		wantFailures FailureCounts
	}{
		{
			name: "restriction", actions: []*rule.Fact{equalAction(term.NewConstant("left"), term.NewConstant("right"))},
			wantFailures: FailureCounts{Restriction: 1},
		},
		{name: "evaluation", rhs: []*rule.Fact{linearFact(branchTestBad, branchTestOverflow())}, wantFailures: FailureCounts{Evaluation: 1}},
		{name: "depth", rhs: []*rule.Fact{linearFact(branchTestFinished)}, wantFailures: FailureCounts{EpsilonDepth: 1}},
	} {
		for name, order := range branchTestArrivals() {
			t.Run(test.name+"/"+name+"/alone", func(t *testing.T) {
				t.Parallel()
				m, _, err := runEvents(t, branchTestNative(test.rhs, test.actions), nil, order...)
				wantRejected(t, m, err)
				wantFailures(t, m, test.wantFailures)
			})
			t.Run(test.name+"/"+name+"/beside a survivor", func(t *testing.T) {
				t.Parallel()
				survivor := triggerRule(branchTestRuleSurvivor, []*rule.Fact{ready}, []*rule.Fact{linearFact(branchTestGood)}, nil, order[1])
				m, _ := acceptEvents(t, append(branchTestNative(test.rhs, test.actions), survivor), []*rule.Fact{ready}, order...)
				wantConfigs(t, m, factProjection(linearFact(branchTestGood)))
				if t.Failed() {
					return
				}
				if pending := m.Configs()[0].pending; len(pending) != 1 {
					t.Errorf("pending applications = %v, want the one of the first event", pending)
				}
				wantFailures(t, m, test.wantFailures)
			})
		}
	}
}

func branchTestOverflow() term.Term {
	return term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant[int64](math.MaxInt64), term.NewConstant[int64](1)})
}

// branchTestFailureTerms returns ground terms whose evaluation fails.
func branchTestFailureTerms() map[string]term.Term {
	intField := term.NewFunction(string(term.FormatIntType), []term.Term{term.NewConstant[int64](256), term.NewConstant[int64](1)})
	return map[string]term.Term{
		"overflow":            branchTestOverflow(),
		"invalid operand":     term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant("text"), term.NewConstant[int64](1)}),
		"format construction": term.NewFunction(term.CatFunctionName, []term.Term{intField}),
	}
}

// branchTestFailingPlace builds the rules in which an evaluation of bad
// fails at one place of candidate processing. The last event of events is
// the one at which it fails.
type branchTestFailingPlace struct {
	rules        func(bad term.Term) []*rule.Rule
	events       []string
	wantFailures FailureCounts
	// wantAlone, if set, replaces wantFailures when the failing rule is
	// the only one.
	wantAlone *FailureCounts
	// remaining are facts that the surviving branch keeps besides Good.
	remaining []*rule.Fact
}

func branchTestFailingPlaces() map[string]branchTestFailingPlace {
	ready := linearFact(branchTestReady)
	return map[string]branchTestFailingPlace{
		// A trigger that cannot be evaluated does not match the event, so
		// alone the configuration has no candidate.
		"matching": {
			rules: func(bad term.Term) []*rule.Rule {
				return []*rule.Rule{triggerRule(branchTestRuleFailing, nil, nil, nil, eventTerm(branchTestEventName, bad))}
			},
			events:    []string{branchTestEventName},
			wantAlone: &FailureCounts{NoCandidate: 1},
		},
		"application": {
			rules: func(bad term.Term) []*rule.Rule {
				return []*rule.Rule{triggerRule(branchTestRuleFailing, nil, []*rule.Fact{linearFact(branchTestBad, bad)}, nil,
					branchTestEvent(branchTestEventName))}
			},
			events:       []string{branchTestEventName},
			wantFailures: FailureCounts{Evaluation: 1},
		},
		"epsilon step": {
			rules: func(bad term.Term) []*rule.Rule {
				return []*rule.Rule{
					triggerRule(branchTestRuleFailing, nil, []*rule.Fact{ready}, nil, branchTestEvent(branchTestEventName)),
					epsilonRule(branchTestRuleAfter, []*rule.Fact{ready}, []*rule.Fact{linearFact(branchTestBad, bad)}, nil),
				}
			},
			events:       []string{branchTestEventName},
			wantFailures: FailureCounts{Evaluation: 1},
		},
		"native completion": {
			rules: func(bad term.Term) []*rule.Rule {
				return []*rule.Rule{triggerRule(branchTestRuleNative, nil, []*rule.Fact{linearFact(branchTestBad, bad)}, nil,
					branchTestEvent(branchTestFirstName), branchTestEvent(branchTestEventName))}
			},
			events:       []string{branchTestFirstName, branchTestEventName},
			wantFailures: FailureCounts{Evaluation: 1},
		},
		// The application of a hinted start fails.
		"hint start": {
			rules: func(bad term.Term) []*rule.Rule {
				return []*rule.Rule{
					triggerRule(branchTestRuleFailing+"Setup", nil, []*rule.Fact{ready}, nil, branchTestEvent(branchTestSetupName)),
					hintRule(branchTestRuleFailing, []*rule.Fact{ready}, []*rule.Fact{linearFact(branchTestBad, bad)}, nil,
						branchTestEvent(branchTestEventName)),
				}
			},
			events:       []string{branchTestSetupName, branchTestEventName},
			wantFailures: FailureCounts{Evaluation: 1},
			remaining:    []*rule.Fact{ready},
		},
	}
}

// TestEvaluationFailuresAreLocal checks failed evaluations (overflow,
// invalid operands, format construction) in matching, rule application,
// the epsilon step, a native completion and a hinted start. Beside a
// surviving rule, in both orders, the failure ends only its candidate.
// Alone, the event is rejected as an ordinary violation and no
// configuration stays live. Only failures after a successful match are
// counted.
func TestEvaluationFailuresAreLocal(t *testing.T) {
	t.Parallel()

	survivor := triggerRule(branchTestRuleSurvivor, nil, []*rule.Fact{linearFact(branchTestGood)}, nil, branchTestEvent(branchTestEventName))
	for termName, bad := range branchTestFailureTerms() {
		for placeName, place := range branchTestFailingPlaces() {
			var events []term.Term
			for _, name := range place.events {
				events = append(events, branchTestEvent(name))
			}
			t.Run(termName+"/"+placeName+"/alone", func(t *testing.T) {
				t.Parallel()
				m, _, err := runEvents(t, place.rules(bad), nil, events...)
				wantRejected(t, m, err)
				want := place.wantFailures
				if place.wantAlone != nil {
					want = *place.wantAlone
				}
				wantFailures(t, m, want)
			})
			for orderName, rules := range branchTestOrders(slices.Concat(place.rules(bad), []*rule.Rule{survivor})...) {
				t.Run(termName+"/"+placeName+"/"+orderName, func(t *testing.T) {
					t.Parallel()
					m, _ := acceptEvents(t, rules, nil, events...)
					wantConfigs(t, m, factProjection(append([]*rule.Fact{linearFact(branchTestGood)}, place.remaining...)...))
					wantFailures(t, m, place.wantFailures)
				})
			}
		}
	}
}

// TestPremiseReservationFailureIsLocal checks a failed evaluation when the
// premises of a native multi-trigger application are reserved. A stored
// premise contains the call of the first trigger, which the reservation
// replaces by its observed result, a string. Its complement then cannot be
// evaluated. Beside a surviving rule, in both orders, only the start fails.
// Alone, the event is rejected.
func TestPremiseReservationFailureIsLocal(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	call := func(arg term.Term) term.Term { return term.NewFunction(branchTestCallName, []term.Term{arg}) }
	complement := func(arg term.Term) term.Term {
		return term.NewFunction(term.NotFunctionName, []term.Term{call(arg)})
	}
	five := term.NewConstant[int64](5)
	stored := linearFact(branchTestFactP, five, complement(five))
	event := term.NewFunction(term.PairFunctionName, []term.Term{call(five), term.NewConstant("text")})
	native := triggerRule(branchTestRuleNative, []*rule.Fact{linearFact(branchTestFactP, x, complement(five))}, []*rule.Fact{linearFact(branchTestDone)}, nil,
		term.NewFunction(term.PairFunctionName, []term.Term{call(x), term.NewVariable("r")}), branchTestEvent(branchTestSecondName))
	survivor := triggerRule(branchTestRuleSurvivor, nil, []*rule.Fact{linearFact(branchTestGood)}, nil,
		term.NewFunction(term.PairFunctionName, []term.Term{call(term.NewVariable("y")), term.NewVariable("z")}))

	t.Run("alone", func(t *testing.T) {
		t.Parallel()
		m, _, err := runEvents(t, []*rule.Rule{native}, []*rule.Fact{stored}, event)
		wantRejected(t, m, err)
		wantFailures(t, m, FailureCounts{Evaluation: 1})
	})
	for name, rules := range branchTestOrders(native, survivor) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, _ := acceptEvents(t, rules, []*rule.Fact{stored}, event)
			wantConfigs(t, m, factProjection(linearFact(branchTestGood), stored))
			wantFailures(t, m, FailureCounts{Evaluation: 1})
		})
	}
}

// TestInvariantFailuresStayFatal checks that a failure that is not local,
// here a restriction with three operands or a rule that is not ground
// after its application, in a rule application, the epsilon step, a native
// completion or a hint continuation, ends the event with that error
// although another rule would accept it.
func TestInvariantFailuresStayFatal(t *testing.T) {
	t.Parallel()

	one := term.NewConstant("1")
	event := branchTestEvent(branchTestEventName)
	ready := []*rule.Fact{linearFact(branchTestReady)}
	finished := []*rule.Fact{linearFact(branchTestFinished)}
	notGround := []*rule.Fact{linearFact(branchTestBad, term.NewVariable("unbound"))}
	survivor := triggerRule(branchTestRuleSurvivor, nil, []*rule.Fact{linearFact(branchTestGood)}, nil, event)
	for name, failing := range map[string][]*rule.Rule{
		"restriction arity": {triggerRule(branchTestRuleFailing, nil, nil, []*rule.Fact{rule.NewFact("Eq", []term.Term{one, one, one}, rule.LinearFact)}, event)},
		"not ground":        {triggerRule(branchTestRuleFailing, nil, notGround, nil, event)},
		"epsilon step":      {triggerRule(branchTestRuleFailing, nil, finished, nil, event), epsilonRule(branchTestRuleAfter, finished, notGround, nil)},
		// The native rule's first trigger is the setup event.
		"native completion": {triggerRule(branchTestRuleNative, nil, notGround, nil, branchTestEvent(branchTestSetupName), event)},
		"hint continuation": {
			hintRule(branchTestRuleFailing, ready, finished, nil, event),
			triggerRule(branchTestRuleAfter, finished, notGround, nil, event),
		},
	} {
		if _, err := NewMonitor(append(failing, survivor)); err == nil {
			t.Fatalf("NewMonitor admitted the %s rules", name)
		}
		// The setup event, which only a native rule consumes, leaves Ready.
		setup := triggerRule("BranchTestSetup", nil, ready, nil, branchTestEvent(branchTestSetupName))
		for orderName, rules := range branchTestOrders(slices.Concat(failing, []*rule.Rule{survivor})...) {
			t.Run(name+"/"+orderName, func(t *testing.T) {
				t.Parallel()
				// Loading rejects the rules. The guards behind it stay.
				m, err := newMonitor(append(rules, setup))
				if err != nil {
					t.Fatalf("newMonitor: %v", err)
				}
				if _, err := m.ProcessEvent(branchTestEvent(branchTestSetupName)); err != nil {
					t.Fatalf("ProcessEvent(setup): %v", err)
				}
				_, err = m.ProcessEvent(event)
				if err == nil || errors.Is(err, ErrNoApplicableRule) || errors.Is(err, ErrRestrictionViolated) || errors.Is(err, term.ErrEvaluation) {
					t.Fatalf("ProcessEvent error = %v, want a fatal error", err)
				}
				wantFailures(t, m, FailureCounts{})
			})
		}
	}
}

// TestRejectedEventLeavesNoLiveConfiguration checks that after an event
// without a surviving branch no configuration is live, so that an event
// that the earlier configurations would accept is rejected as well. The
// configurations before the rejection remain for the diagnostics only.
func TestRejectedEventLeavesNoLiveConfiguration(t *testing.T) {
	t.Parallel()

	ready := linearFact(branchTestReady)
	keep := triggerRule("BranchTestKeep", []*rule.Fact{ready}, []*rule.Fact{ready}, nil, branchTestEvent(branchTestEventName))
	m, _, err := runEvents(t, []*rule.Rule{keep}, []*rule.Fact{ready}, branchTestEvent(branchTestEventName), branchTestEvent(branchTestOtherName))
	wantRejected(t, m, err)
	m.logFinalConfigs()
	if configs := m.Configs(); len(configs) != 0 {
		t.Fatalf("logging the final configurations made %v live", configs)
	}
	_, err = m.ProcessEvent(branchTestEvent(branchTestEventName))
	wantRejected(t, m, err)
	wantFailures(t, m, FailureCounts{NoCandidate: 1})
}

// outputActions returns the actions that emit events as rewrite outputs.
func outputActions(events ...term.Term) []*rule.Fact {
	var actions []*rule.Fact
	for _, event := range events {
		actions = append(actions, rule.NewFact(rule.RewriteEventName, []term.Term{event}, rule.LinearFact))
	}
	return actions
}

// runPipeline runs events through rewriter and main.
func runPipeline(t *testing.T, rewriter, main *Monitor, events ...term.Term) (*ViolationInfo, error) {
	t.Helper()
	return RunPipeline(context.Background(), rewriter, main, failureTrace(t, events...), nil)
}

// wantNoPipelineConfigs checks that neither monitor of a pipeline has a
// live configuration.
func wantNoPipelineConfigs(t *testing.T, rewriter, main *Monitor) {
	t.Helper()
	if len(rewriter.Configs()) != 0 || len(main.Configs()) != 0 {
		t.Fatalf("configurations after the rejection = %v, %v; want none", rewriter.Configs(), main.Configs())
	}
}

// TestRunPipelineEvaluationFailures checks that a failed evaluation in a
// rewrite rule or in a rule of the main monitor ends only its branch:
// beside a surviving rule, in both orders, the event is accepted. Alone,
// on the rewrite side it is the rewrite violation error without a
// violation report, and in the main monitor an ordinary violation at the
// rewritten event. After a rejection no configuration stays live.
func TestRunPipelineEvaluationFailures(t *testing.T) {
	t.Parallel()

	input := branchTestEvent(branchTestEventName)
	output := branchTestEvent(branchTestOutputName)
	bad := []*rule.Fact{linearFact(branchTestBad, branchTestOverflow())}
	rewrite := []*rule.Rule{triggerRule("PipelineLocalRewrite", nil, nil, outputActions(output), input)}
	main := []*rule.Rule{triggerRule("PipelineLocalMain", nil, []*rule.Fact{linearFact(branchTestGood)}, nil, output)}
	failingRewrite := triggerRule("PipelineLocalRewriteFailing", nil, bad, outputActions(output), input)
	failingMain := triggerRule("PipelineLocalMainFailing", nil, bad, nil, output)
	for _, test := range []struct {
		name          string
		rewrite, main []*rule.Rule
		// rejectedBy is the monitor that rejects the event, if any.
		rejectedBy string
	}{
		{name: "rewrite/failing first", rewrite: append([]*rule.Rule{failingRewrite}, rewrite...), main: main},
		{name: "rewrite/surviving first", rewrite: append(slices.Clone(rewrite), failingRewrite), main: main},
		{name: "rewrite/alone", rewrite: []*rule.Rule{failingRewrite}, main: main, rejectedBy: FailureMonitorRewrite},
		{name: "main/failing first", rewrite: rewrite, main: append([]*rule.Rule{failingMain}, main...)},
		{name: "main/surviving first", rewrite: rewrite, main: append(slices.Clone(main), failingMain)},
		{name: "main/alone", rewrite: rewrite, main: []*rule.Rule{failingMain}, rejectedBy: FailureMonitorCore},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rewriter, core := newEpsilonTestMonitor(t, test.rewrite...), newEpsilonTestMonitor(t, test.main...)
			violation, err := runPipeline(t, rewriter, core, input)
			switch test.rejectedBy {
			case "":
				if violation != nil || err != nil {
					t.Fatalf("RunPipeline = (%v, %v), want acceptance", violation, err)
				}
				if configs := core.Configs(); len(configs) != 1 || configs[0].CountByName(branchTestGood) != 1 {
					t.Fatalf("main configurations = %v, want the surviving branch", configs)
				}
				return
			case FailureMonitorRewrite:
				if violation != nil || !errors.Is(err, ErrNoApplicableRule) || errors.Is(err, term.ErrEvaluation) ||
					!strings.Contains(err.Error(), "rewrite violation") {
					t.Fatalf("RunPipeline = (%v, %v), want the rewrite violation error", violation, err)
				}
			default:
				if err != nil || violation == nil || !errors.Is(violation.Err, ErrNoApplicableRule) ||
					!violation.TimedEvent.Event.Equal(output) || violation.EventIndex != 1 {
					t.Fatalf("RunPipeline = (%+v, %v), want a violation at the rewritten event", violation, err)
				}
			}
			wantNoPipelineConfigs(t, rewriter, core)
		})
	}
}

// TestRunPipelineRejectionLeavesNoLiveConfiguration checks that after a
// rejected event no pipeline branch stays live: an event that the earlier
// configurations would accept is rejected by a later run. Without input,
// the initial configurations stay live.
func TestRunPipelineRejectionLeavesNoLiveConfiguration(t *testing.T) {
	t.Parallel()

	input := branchTestEvent(branchTestEventName)
	other := branchTestEvent(branchTestOtherName)
	output := branchTestEvent(branchTestOutputName)
	for _, test := range []struct {
		name   string
		events []term.Term
		// rewrite is set when the rewriter rejects the last event.
		rewrite bool
	}{
		{name: "empty input"},
		// The main monitor has no rule for the second output.
		{name: "main rejection", events: []term.Term{input, other}},
		{name: "rewrite rejection", events: []term.Term{output}, rewrite: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rewriter := newEpsilonTestMonitor(t,
				triggerRule("PipelineLocalRewriteInput", nil, nil, outputActions(output), input),
				triggerRule("PipelineLocalRewriteOther", nil, nil, outputActions(other), other))
			main := newEpsilonTestMonitor(t, triggerRule("PipelineLocalMain", nil, nil, nil, output))
			violation, err := runPipeline(t, rewriter, main, test.events...)
			switch {
			case test.events == nil:
				if violation != nil || err != nil {
					t.Fatalf("RunPipeline = (%v, %v), want acceptance", violation, err)
				}
				if len(rewriter.Configs()) != 1 || len(main.Configs()) != 1 {
					t.Fatalf("configurations = %v, %v; want the initial ones", rewriter.Configs(), main.Configs())
				}
				return
			case test.rewrite && (violation != nil || !errors.Is(err, ErrNoApplicableRule)):
				t.Fatalf("RunPipeline = (%v, %v), want the rewrite violation error", violation, err)
			case !test.rewrite && (err != nil || violation == nil):
				t.Fatalf("RunPipeline = (%v, %v), want a violation", violation, err)
			}
			wantNoPipelineConfigs(t, rewriter, main)
			if violation, err := runPipeline(t, rewriter, main, input); violation == nil && err == nil {
				t.Fatal("RunPipeline after the rejection accepted an event")
			}
		})
	}
}

// TestRunPipelineWithoutLiveMainConfiguration checks a main monitor that
// has rejected an event before, through ProcessEvent: raw events that emit
// nothing are still accepted, and the first rewritten event is a violation
// of the main monitor.
func TestRunPipelineWithoutLiveMainConfiguration(t *testing.T) {
	t.Parallel()

	input := branchTestEvent(branchTestEventName)
	silent := branchTestEvent(branchTestOtherName)
	output := branchTestEvent(branchTestOutputName)
	rewriter := newEpsilonTestMonitor(t,
		triggerRule("PipelineEmptyMainOutput", nil, nil, outputActions(output), input),
		triggerRule("PipelineEmptyMainSilent", nil, nil, nil, silent))
	main := newEpsilonTestMonitor(t, triggerRule("PipelineEmptyMain", nil, nil, nil, output))
	if _, err := main.ProcessEvent(silent); !errors.Is(err, ErrNoApplicableRule) {
		t.Fatalf("ProcessEvent error = %v, want ErrNoApplicableRule", err)
	}
	violation, err := runPipeline(t, rewriter, main, silent, silent, input)
	if err != nil || violation == nil || !violation.TimedEvent.Event.Equal(output) {
		t.Fatalf("RunPipeline = (%+v, %v), want a violation of the main monitor at %s", violation, err, output)
	}
}

// TestRunPipelineLogsAllowedEventsOfTheRejectingSide checks that a rejection
// in the pipeline logs the events that the rejecting side allows: the
// rewrite configurations for a raw event that no rewrite rule accepts, and
// the core configurations of a failed alternative with its position.
func TestRunPipelineLogsAllowedEventsOfTheRejectingSide(t *testing.T) {
	var logged bytes.Buffer
	output, level := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(&logged)
	log.SetLevel(log.WarnLevel)
	t.Cleanup(func() {
		log.SetOutput(output)
		log.SetLevel(level)
	})

	input := branchTestEvent(branchTestEventName)
	other := branchTestEvent(branchTestOtherName)
	emitted := branchTestEvent(branchTestOutputName)
	for _, test := range []struct {
		name     string
		raw      term.Term
		headings []string
		allowed  string
	}{
		{"main", input, []string{
			"allowed events in core configuration 0 (raw event 1, alternative 1, position 1):",
			"allowed events in core configuration 0 (raw event 1, alternative 2, position 2):",
		}, branchTestOtherName},
		{"rewrite", other, []string{"allowed raw events in rewrite configuration 0:"}, branchTestEventName},
	} {
		logged.Reset()
		rewriter := newEpsilonTestMonitor(t, triggerRule("PipelineAllowedRewrite", nil, nil, outputActions(emitted), input),
			triggerRule("PipelineAllowedRewriteLong", nil, nil, outputActions(other, emitted), input))
		main := newEpsilonTestMonitor(t, triggerRule("PipelineAllowedMain", nil, nil, nil, other))
		if violation, err := runPipeline(t, rewriter, main, test.raw); violation == nil && err == nil {
			t.Fatalf("%s: RunPipeline accepted %s", test.name, test.raw)
		}
		text := logged.String()
		for _, heading := range test.headings {
			at := strings.Index(text, heading)
			if at < 0 || !strings.Contains(text[at:], test.allowed) {
				t.Fatalf("%s: log = %q, want %q followed by an event of %s", test.name, text, heading, test.allowed)
			}
		}
		// The final configurations are those from which the event was rejected.
		if strings.Contains(text, "final configurations (0)") {
			t.Fatalf("%s: log = %q, want the final configurations before the rejection", test.name, text)
		}
	}
	logged.Reset()
	if runFailureTrace(t, newEpsilonTestMonitor(t, triggerRule("PipelineAllowedMain", nil, nil, nil, other)), input) == nil {
		t.Fatalf("Run accepted %s", input)
	}
	if text := logged.String(); strings.Contains(text, "final configurations (0)") {
		t.Fatalf("log = %q, want the final configurations before the rejection", text)
	}
}

// TestRunPipelineInvariantFailuresAreFatal checks that a failure that
// loading excludes, a rewrite output that is not a pair or a rule of the
// main monitor that is not ground beside a surviving rule, ends the run
// with an error.
func TestRunPipelineInvariantFailuresAreFatal(t *testing.T) {
	t.Parallel()

	input := branchTestEvent(branchTestEventName)
	output := branchTestEvent(branchTestOutputName)
	unchecked := func(rules ...*rule.Rule) *Monitor {
		m, err := newMonitor(rules)
		if err != nil {
			t.Fatalf("newMonitor: %v", err)
		}
		return m
	}
	for _, test := range []struct {
		name           string
		rewriter, main *Monitor
		want           string
	}{
		{
			name:     "output that is not a pair",
			rewriter: unchecked(triggerRule("PipelineNotAPair", nil, nil, outputActions(term.NewFunction(branchTestOutputName, nil)), input)),
			main:     newEpsilonTestMonitor(t),
			want:     "is not a pair",
		},
		{
			name:     "main rule not ground",
			rewriter: newEpsilonTestMonitor(t, triggerRule("PipelineLocalRewrite", nil, nil, outputActions(output), input)),
			main: unchecked(triggerRule("PipelineNotGround", nil, []*rule.Fact{linearFact(branchTestBad, term.NewVariable("unbound"))}, nil, output),
				triggerRule("PipelineLocalMain", nil, nil, nil, output)),
			want: "expected ground rule",
		},
	} {
		if violation, err := runPipeline(t, test.rewriter, test.main, input); violation != nil || err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: RunPipeline = (%v, %v), want an error with %q", test.name, violation, err, test.want)
		}
	}
}

// TestRunPipelineOutputWithoutCallHasNoCandidate checks that a rewrite
// output whose first component is not a call ends only its alternative,
// as an event that no rule of the main monitor matches.
func TestRunPipelineOutputWithoutCallHasNoCandidate(t *testing.T) {
	t.Parallel()

	value := term.NewVariable("pipelineLocalValue")
	input := eventTerm(branchTestEventName, term.NewConstant[int64](5))
	trigger := eventTerm(branchTestEventName, value)
	output := branchTestEvent(branchTestOutputName)
	withoutCall := triggerRule("PipelineLocalWithoutCall", nil, nil,
		outputActions(term.NewFunction(term.PairFunctionName, []term.Term{value, failureUnit()})), trigger)
	main := triggerRule("PipelineLocalMain", nil, nil, nil, output)

	t.Run("beside a valid alternative", func(t *testing.T) {
		t.Parallel()
		rewriter := newEpsilonTestMonitor(t, withoutCall, triggerRule("PipelineLocalWithCall", nil, nil, outputActions(output), trigger))
		if violation, err := runPipeline(t, rewriter, newEpsilonTestMonitor(t, main), input); violation != nil || err != nil {
			t.Fatalf("RunPipeline = (%v, %v), want acceptance", violation, err)
		}
	})
	t.Run("alone", func(t *testing.T) {
		t.Parallel()
		core := newEpsilonTestMonitor(t, main)
		initial := core.Configs()[0].Hash()
		violation, err := runPipeline(t, newEpsilonTestMonitor(t, withoutCall), core, input)
		if err != nil || violation == nil || !errors.Is(violation.Err, ErrNoApplicableRule) {
			t.Fatalf("RunPipeline = (%v, %v), want a violation of the main monitor", violation, err)
		}
		want := term.NewFunction(term.PairFunctionName, []term.Term{term.NewConstant[int64](5), failureUnit()})
		if !violation.TimedEvent.Event.Equal(want) || violation.EventIndex != 1 {
			t.Fatalf("violation at %s (index %d), want %s at 1", violation.TimedEvent.Event, violation.EventIndex, want)
		}
		final := violation.Failures.Final
		if len(final) != 1 || final[0].Monitor != FailureMonitorCore || final[0].Category != FailureNoCandidate ||
			final[0].Rewrite == nil || *final[0].Rewrite != (RewritePosition{RawEvent: 1, Alternative: 1, Position: 1}) {
			t.Fatalf("final records = %+v, want one core record without a candidate", final)
		}
		if final[0].Branch != initial {
			t.Fatalf("record branch %x, want the initial configuration %x", final[0].Branch, initial)
		}
	})
}
