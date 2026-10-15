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
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

func TestRecordPipelineOutputsUsesReceivedLatency(t *testing.T) {
	main, err := NewMonitor(nil)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	outputs := []term.Term{
		term.NewFunction("pipelineStatsFirst", nil),
		term.NewFunction("pipelineStatsSecond", nil),
		term.NewFunction("pipelineStatsThird", nil),
	}
	const processingTime = 10 * time.Millisecond
	eventTime := time.Now().Add(-processingTime).UnixNano()

	if err := recordPipelineOutputs(
		main,
		eventTime,
		outputs,
		0,
		nil,
	); err != nil {
		t.Fatalf("recordPipelineOutputs: %v", err)
	}

	summary := main.stats.Summary(time.Now())
	if summary.Processed != len(outputs) {
		t.Fatalf("processed = %d, want %d", summary.Processed, len(outputs))
	}
	if summary.AvgProcessingTimeNS < processingTime.Nanoseconds() {
		t.Fatalf("average processing time = %d, want at least %d", summary.AvgProcessingTimeNS, processingTime)
	}
}

func TestDedupePipelineTransitionsConverges(t *testing.T) {
	const (
		rewriteFactName = "PipelineDedupeRewrite"
		firstFactName   = "PipelineDedupeFirst"
		secondFactName  = "PipelineDedupeSecond"
		outputEventName = "pipelineDedupeOutput"
	)

	rewriteConfig := NewConfig()
	rewriteConfig.AddFact(rule.NewFact(rewriteFactName, nil, rule.LinearFact))
	firstMainConfig := NewConfig()
	firstMainConfig.AddFact(rule.NewFact(firstFactName, nil, rule.LinearFact))
	secondMainConfig := NewConfig()
	secondMainConfig.AddFact(rule.NewFact(secondFactName, nil, rule.LinearFact))
	unit := term.NewFunction(term.PairFunctionName, nil)

	transitions := []pipelineTransition{
		{
			state: pipelineState{
				rewrite: rewriteConfig,
				main:    []*Config{firstMainConfig, secondMainConfig},
			},
			outputs: []*term.Function{eventTerm(outputEventName, unit)},
		},
		{
			state: pipelineState{
				rewrite: rewriteConfig.Clone(),
				main:    []*Config{secondMainConfig.Clone(), firstMainConfig.Clone()},
			},
			outputs: []*term.Function{eventTerm(outputEventName, unit)},
		},
	}

	if got := dedupePipelineTransitions(transitions); len(got) != 1 {
		t.Fatalf("dedupePipelineTransitions returned %d transitions, want 1", len(got))
	}
}

// runTestPipeline runs RunPipeline over events with a rewriter of
// rewriteRules and a main monitor of mainRules. It returns both monitors,
// the consumed events and the result.
func runTestPipeline(t *testing.T, rewriteRules, mainRules []*rule.Rule, events ...*term.Function) (*Monitor, *Monitor, []string, *ViolationInfo, error) {
	t.Helper()
	rewriter, err := NewMonitor(rewriteRules)
	if err != nil {
		t.Fatalf("NewMonitor rewriter: %v", err)
	}
	main, err := NewMonitor(mainRules)
	if err != nil {
		t.Fatalf("NewMonitor main: %v", err)
	}
	var input strings.Builder
	for _, event := range events {
		line, err := json.Marshal(&TimedEvent{Time: time.Now().UnixNano(), Event: event})
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		input.Write(append(line, '\n'))
	}
	var consumed []string
	violation, err := RunPipeline(context.Background(), rewriter, main, io.NopCloser(strings.NewReader(input.String())),
		func(event term.Term) error {
			consumed = append(consumed, event.String())
			return nil
		})
	return rewriter, main, consumed, violation, err
}

// emitEvents returns rewrite actions that emit events in order.
func emitEvents(events ...*term.Function) []*rule.Fact {
	actions := make([]*rule.Fact, len(events))
	for i, event := range events {
		actions[i] = rule.NewFact(rule.RewriteEventName, []term.Term{event}, rule.LinearFact)
	}
	return actions
}

// TestRunPipelinePairsRewriteAndMainStates checks that the main monitor
// continues from the configurations that its own rewrite branch reached.
// Rewrite branch A emits a() and then ends. Branch B emits nothing for the
// first raw event and c() for the second. The main monitor accepts c() only
// after a(), which was emitted on the other branch, so c() is a violation.
// With a union of the main configurations of both branches it would be
// accepted.
func TestRunPipelinePairsRewriteAndMainStates(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	a, c := eventTerm("pairedA", unit), eventTerm("pairedC", unit)
	state := func(name string) []*rule.Fact { return []*rule.Fact{rule.NewFact(name, nil, rule.LinearFact)} }
	rewriter, main, consumed, violation, err := runTestPipeline(t, []*rule.Rule{
		triggerRule("PairedRewriteA", nil, state("PairedRewriteDoneA"), emitEvents(a), eventTerm("pairedFirst", unit)),
		triggerRule("PairedRewriteB", nil, state("PairedRewriteDoneB"), nil, eventTerm("pairedFirst", unit)),
		triggerRule("PairedRewriteC", state("PairedRewriteDoneB"), nil, emitEvents(c), eventTerm("pairedSecond", unit)),
	}, []*rule.Rule{
		triggerRule("PairedMainA", nil, state("PairedMainSeenA"), nil, a),
		triggerRule("PairedMainC", state("PairedMainSeenA"), nil, nil, c),
	}, eventTerm("pairedFirst", unit), eventTerm("pairedSecond", unit))
	if err != nil || violation == nil || !violation.TimedEvent.Event.Equal(c) {
		t.Fatalf("RunPipeline = (%+v, %v), want the violation at pairedC", violation, err)
	}
	if want := []string{a.String()}; !slices.Equal(consumed, want) {
		t.Fatalf("consumed = %q, want %q", consumed, want)
	}
	// Both monitors keep the configurations before the rejected event.
	wantConfigs(t, rewriter, factProjection(state("PairedRewriteDoneA")...), factProjection(state("PairedRewriteDoneB")...))
	wantConfigs(t, main, factProjection(), factProjection(state("PairedMainSeenA")...))
}

// TestRunPipelineReportsFailureWithinRewriteOutputSequence checks a raw
// event whose second output is rejected: the first is consumed, the
// violation names the second, and the failed transition is not published.
func TestRunPipelineReportsFailureWithinRewriteOutputSequence(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	first, second := eventTerm("pipelineSequenceFirst", unit), eventTerm("pipelineSequenceSecond", unit)
	ready := []*rule.Fact{rule.NewFact("PipelineSequenceReady", nil, rule.LinearFact)}
	_, main, consumed, violation, err := runTestPipeline(t,
		[]*rule.Rule{triggerRule("PipelineSequenceRewrite", nil, nil, emitEvents(first, second), eventTerm("pipelineSequenceInput", unit))},
		[]*rule.Rule{
			triggerRule("PipelineSequenceFirstRule", nil, ready, nil, first),
			triggerRule("PipelineSequenceFollowRule", ready, nil, nil, eventTerm("pipelineSequenceFollow", unit)),
		},
		eventTerm("pipelineSequenceInput", unit))
	if err != nil || violation == nil || !errors.Is(violation.Err, ErrNoApplicableRule) {
		t.Fatalf("RunPipeline = (%v, %v), want second output violation", violation, err)
	}
	if want := []string{first.String()}; !slices.Equal(consumed, want) {
		t.Fatalf("consumed outputs = %q, want %q", consumed, want)
	}
	if !violation.TimedEvent.Event.Equal(second) || violation.EventIndex != 2 ||
		violation.Stats.Received != 2 || violation.Stats.Processed != 1 {
		t.Fatalf("unexpected output-sequence violation: %+v", violation)
	}
	wantConfigs(t, main, factProjection())
}

// TestRunPipelineConsumesEqualOutputsOnce checks that two rewrite branches
// that emit the same output report it once.
func TestRunPipelineConsumesEqualOutputsOnce(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	out, in := eventTerm("equalOutput", unit), eventTerm("equalInput", unit)
	state := func(name string) []*rule.Fact { return []*rule.Fact{rule.NewFact(name, nil, rule.LinearFact)} }
	_, _, consumed, violation, err := runTestPipeline(t, []*rule.Rule{
		triggerRule("EqualRewriteA", nil, state("EqualRewriteA"), emitEvents(out), in),
		triggerRule("EqualRewriteB", nil, state("EqualRewriteB"), emitEvents(out), in),
	}, []*rule.Rule{triggerRule("EqualMain", nil, nil, nil, out)}, in)
	if err != nil || violation != nil || !slices.Equal(consumed, []string{out.String()}) {
		t.Fatalf("RunPipeline = (%v, %v), consumed %q, want %s once", violation, err, consumed, out)
	}
}
