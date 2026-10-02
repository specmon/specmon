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

package monitor_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

const (
	runnerInputEventName  = "runnerInput"
	runnerOutputEventName = "runnerOutput"
	runnerRuleName        = "RunnerRule"
	runnerValueName       = "runnerValue"
)

type closeTrackingReader struct {
	io.Reader
	closes atomic.Int32
}

func (r *closeTrackingReader) Close() error {
	r.closes.Add(1)
	return nil
}

type blockingReader struct {
	data      []byte
	readOnce  sync.Once
	closeOnce sync.Once
	closed    chan struct{}
	blocked   chan struct{}
	closes    atomic.Int32
}

func newBlockingReader(data []byte) *blockingReader {
	return &blockingReader{
		data:    data,
		closed:  make(chan struct{}),
		blocked: make(chan struct{}),
	}
}

func (r *blockingReader) Read(p []byte) (int, error) {
	read := false
	r.readOnce.Do(func() {
		read = true
	})
	if read && len(r.data) > 0 {
		return copy(p, r.data), nil
	}

	select {
	case <-r.blocked:
	default:
		close(r.blocked)
	}
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *blockingReader) Close() error {
	r.closes.Add(1)
	r.closeOnce.Do(func() {
		close(r.closed)
	})
	return nil
}

func runnerEvent(name string, value term.Term) *term.Function {
	return term.NewFunction(term.PairFunctionName, []term.Term{
		term.NewFunction(name, nil),
		value,
	})
}

func runnerEventLine(t *testing.T, event *term.Function) []byte {
	t.Helper()
	b, err := json.Marshal(&monitor.TimedEvent{Time: time.Now().UnixNano(), Event: event})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return append(b, '\n')
}

func acceptingRunnerMonitor(t *testing.T) *monitor.Monitor {
	t.Helper()
	r := &rule.Rule{
		Name: runnerRuleName,
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{
				runnerEvent(runnerInputEventName, term.NewVariable(runnerValueName)),
			}},
		},
	}
	m, err := monitor.NewMonitor([]*rule.Rule{r})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	return m
}

// rewritingRunnerMonitor rewrites each input event into an output event
// with the same value.
func rewritingRunnerMonitor(t *testing.T) *monitor.Monitor {
	t.Helper()
	value := term.NewVariable(runnerValueName)
	r := &rule.Rule{
		Name: runnerRuleName,
		Act: []*rule.Fact{
			rule.NewFact(monitor.RewriteEventName, []term.Term{
				runnerEvent(runnerOutputEventName, value),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{
				runnerEvent(runnerInputEventName, value),
			}},
		},
	}
	m, err := monitor.NewMonitor([]*rule.Rule{r})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	return m
}

func TestStatsSummaryDoesNotMutateSamples(t *testing.T) {
	t.Parallel()

	start := time.Unix(100, 0)
	received := []time.Duration{3 * time.Nanosecond, time.Nanosecond, 2 * time.Nanosecond}
	processed := []time.Duration{5 * time.Nanosecond, 4 * time.Nanosecond}
	stats := &monitor.Stats{
		LatenciesReceived:  append([]time.Duration(nil), received...),
		LatenciesProcessed: append([]time.Duration(nil), processed...),
		StartTime:          start,
	}

	summary := stats.Summary(start.Add(10 * time.Nanosecond))
	if summary.Received != 3 || summary.Processed != 2 || summary.TotalTimeNS != 10 {
		t.Fatalf("unexpected counts or total: %+v", summary)
	}
	if summary.AvgLatencyReceivedNS != 2 || summary.MedLatencyReceivedNS != 2 {
		t.Fatalf("unexpected received latency summary: %+v", summary)
	}
	if summary.AvgLatencyProcessedNS != 4 || summary.MedLatencyProcessedNS != 4 {
		t.Fatalf("unexpected processed latency summary: %+v", summary)
	}
	if summary.AvgProcessingTimeNS != 2 {
		t.Fatalf("unexpected processing time summary: %+v", summary)
	}
	for i := range received {
		if stats.LatenciesReceived[i] != received[i] {
			t.Fatalf("Summary reordered received samples: %v", stats.LatenciesReceived)
		}
	}
	for i := range processed {
		if stats.LatenciesProcessed[i] != processed[i] {
			t.Fatalf("Summary reordered processed samples: %v", stats.LatenciesProcessed)
		}
	}

	if got := (&monitor.Stats{}).Summary(time.Now()); got != (monitor.StatsSummary{}) {
		t.Fatalf("empty Summary = %+v, want zero value", got)
	}
}

func TestProcessEventsReturnsImmutableViolationSnapshot(t *testing.T) {
	t.Parallel()

	m, err := monitor.NewMonitor(nil)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	event := &monitor.TimedEvent{
		Time:  time.Now().UnixNano(),
		Event: runnerEvent(runnerInputEventName, term.NewConstant([]byte{1, 2, 3})),
	}
	events := make(chan *monitor.TimedEvent, 1)
	events <- event
	close(events)

	streams := m.ProcessEvents(context.Background(), events, false)
	for range streams.Outputs {
	}
	for range streams.Consumed {
	}
	var results []monitor.StreamResult
	for result := range streams.Terminal {
		results = append(results, result)
	}
	if len(results) != 1 {
		t.Fatalf("terminal channel returned %d results, want one", len(results))
	}
	result := results[0]
	if result.Err != nil || result.Violation == nil {
		t.Fatalf("terminal result = %+v, want violation", result)
	}
	violation := result.Violation
	if !errors.Is(violation.Err, monitor.ErrNoApplicableRule) ||
		violation.ErrorKind != monitor.ViolationKindNoApplicableRule {
		t.Fatalf("unexpected violation classification: %+v", violation)
	}
	if violation.EventIndex != 1 || violation.Stats.Received != 1 || violation.Stats.Processed != 0 {
		t.Fatalf("unexpected violation position or stats: %+v", violation)
	}

	originalBytes := event.Event.Args[1].(*term.Constant[[]byte])
	originalBytes.Value[0] = 9
	event.Event.Args[1] = term.NewConstant("changed")
	clonedBytes := violation.TimedEvent.Event.Args[1].(*term.Constant[[]byte])
	if clonedBytes.Value[0] != 1 {
		t.Fatalf("violation snapshot retained mutable event data: %v", clonedBytes.Value)
	}
}

func TestProcessEventsReturnsNilEventErrors(t *testing.T) {
	t.Parallel()

	m, err := monitor.NewMonitor(nil)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	events := make(chan *monitor.TimedEvent, 1)
	events <- nil
	close(events)

	streams := m.ProcessEvents(context.Background(), events, false)
	for range streams.Outputs {
	}
	for range streams.Consumed {
	}
	result := <-streams.Terminal
	if result.Err == nil || result.Violation != nil {
		t.Fatalf("terminal result = %+v, want ordinary nil event error", result)
	}
}

func TestRunReturnsParseErrorsAndClosesInput(t *testing.T) {
	t.Parallel()

	m, err := monitor.NewMonitor(nil)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	reader := &closeTrackingReader{Reader: strings.NewReader("not json\n")}
	violation, err := m.Run(context.Background(), reader, nil)
	if violation != nil || err == nil {
		t.Fatalf("Run = (%v, %v), want ordinary parse error", violation, err)
	}
	if reader.closes.Load() != 1 {
		t.Fatalf("input closed %d times, want once", reader.closes.Load())
	}
}

func TestRunCallbackErrorClosesBlockingInput(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("consumed callback failed")
	reader := newBlockingReader(runnerEventLine(t, runnerEvent(runnerInputEventName, term.NewConstant(1))))
	violation, err := acceptingRunnerMonitor(t).Run(context.Background(), reader, func(term.Term) error {
		return wantErr
	})
	if violation != nil || !errors.Is(err, wantErr) {
		t.Fatalf("Run = (%v, %v), want callback error", violation, err)
	}
	if reader.closes.Load() != 1 {
		t.Fatalf("input closed %d times, want once", reader.closes.Load())
	}
}

func TestRunCancellationClosesBlockingInput(t *testing.T) {
	t.Parallel()

	reader := newBlockingReader(nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-reader.blocked
		cancel()
	}()

	violation, err := acceptingRunnerMonitor(t).Run(ctx, reader, nil)
	if violation != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = (%v, %v), want context cancellation", violation, err)
	}
	if reader.closes.Load() != 1 {
		t.Fatalf("input closed %d times, want once", reader.closes.Load())
	}
}

// stuckReader returns its data once and then blocks until the test ends,
// whether or not it is closed, like a read from a pipe or a terminal.
type stuckReader struct {
	data     []byte
	readOnce sync.Once
	release  chan struct{}
}

func newStuckReader(t *testing.T, data []byte) *stuckReader {
	r := &stuckReader{data: data, release: make(chan struct{})}
	t.Cleanup(func() { close(r.release) })
	return r
}

func (r *stuckReader) Read(p []byte) (int, error) {
	read := false
	r.readOnce.Do(func() {
		read = true
	})
	if read {
		return copy(p, r.data), nil
	}
	<-r.release
	return 0, io.EOF
}

func (r *stuckReader) Close() error {
	return nil
}

func TestRunReportsViolationWhileReadBlocks(t *testing.T) {
	t.Parallel()

	reader := newStuckReader(t, runnerEventLine(t, runnerEvent(runnerOutputEventName, term.NewConstant(1))))
	type result struct {
		violation *monitor.ViolationInfo
		err       error
	}
	done := make(chan result, 1)
	go func() {
		violation, err := acceptingRunnerMonitor(t).Run(context.Background(), reader, nil)
		done <- result{violation, err}
	}()
	select {
	case got := <-done:
		if got.violation == nil || got.err != nil {
			t.Fatalf("Run = (%v, %v), want the violation", got.violation, got.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run waits for the blocked read after the violation")
	}
}

func TestRunReportsViolationBeforeLaterParseError(t *testing.T) {
	t.Parallel()

	for _, accepted := range []int{0, 10, 200, 2000} {
		var input strings.Builder
		for i := range accepted {
			input.Write(runnerEventLine(t, runnerEvent(runnerInputEventName, term.NewConstant(i))))
		}
		input.Write(runnerEventLine(t, runnerEvent(runnerOutputEventName, term.NewConstant(1))))
		input.WriteString("{\"time\": 1, \"event\": \n")
		violation, err := acceptingRunnerMonitor(t).Run(context.Background(), io.NopCloser(strings.NewReader(input.String())), nil)
		if violation == nil || err != nil || violation.EventIndex != accepted+1 {
			t.Fatalf("%d accepted events: Run = (%+v, %v), want the violation at event %d", accepted, violation, err, accepted+1)
		}
	}
}

func TestRunPreservesStatsAndClassifiesAcceptedHintViolations(t *testing.T) {
	t.Parallel()

	const (
		setupEventName = "runnerSetup"
		hintEventName  = "runnerHint"
		stateFactName  = "RunnerState"
		setupRuleName  = "RunnerSetup"
		hintRuleName   = "RunnerHint"
	)
	setupEvent := runnerEvent(setupEventName, term.NewFunction(term.PairFunctionName, nil))
	hintEvent := runnerEvent(hintEventName, term.NewConstant(1))
	setupRule := &rule.Rule{
		Name: setupRuleName,
		RHS:  []*rule.Fact{rule.NewFact(stateFactName, nil, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{setupEvent}},
		},
	}
	hintRule := &rule.Rule{
		Name: hintRuleName,
		LHS:  []*rule.Fact{rule.NewFact(stateFactName, nil, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			rule.HintAttributeName: rule.TermAttribute{Value: []term.Term{
				runnerEvent(hintEventName, term.NewVariable(runnerValueName)),
			}},
		},
	}
	m, err := monitor.NewMonitor([]*rule.Rule{setupRule, hintRule})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}

	first := &closeTrackingReader{Reader: strings.NewReader(string(runnerEventLine(t, setupEvent)))}
	violation, err := m.Run(context.Background(), first, nil)
	if violation != nil || err != nil {
		t.Fatalf("setup Run = (%v, %v), want success", violation, err)
	}
	start := m.Stats().StartTime

	second := &closeTrackingReader{Reader: strings.NewReader(string(runnerEventLine(t, hintEvent)))}
	violation, err = m.Run(context.Background(), second, nil)
	if err != nil || violation == nil || !errors.Is(violation.Err, monitor.ErrNoApplicableRule) {
		t.Fatalf("hint Run = (%v, %v), want no applicable rule violation", violation, err)
	}
	if violation.ErrorKind != monitor.ViolationKindNoApplicableRule {
		t.Fatalf("hint violation kind = %q", violation.ErrorKind)
	}
	if violation.EventIndex != 2 || violation.Stats.Received != 2 || violation.Stats.Processed != 1 {
		t.Fatalf("hint violation lost cumulative position or stats: %+v", violation)
	}
	if !m.Stats().StartTime.Equal(start) {
		t.Fatalf("second Run reset monitor start time: first %s, second %s", start, m.Stats().StartTime)
	}
}

func TestRewriteCallbackErrorClosesBlockingInput(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("output callback failed")
	m := rewritingRunnerMonitor(t)
	reader := newBlockingReader(runnerEventLine(t, runnerEvent(runnerInputEventName, term.NewConstant(1))))
	err := m.Rewrite(context.Background(), reader, func(*monitor.TimedEvent) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Rewrite error = %v, want callback error", err)
	}
	if reader.closes.Load() != 1 {
		t.Fatalf("input closed %d times, want once", reader.closes.Load())
	}
}

func TestRewriteViolationNamesEvent(t *testing.T) {
	t.Parallel()

	rejected := runnerEvent(runnerOutputEventName, term.NewFunction(term.PairFunctionName, nil))
	input := append(runnerEventLine(t, runnerEvent(runnerInputEventName, term.NewConstant(1))), runnerEventLine(t, rejected)...)
	err := rewritingRunnerMonitor(t).Rewrite(context.Background(), io.NopCloser(strings.NewReader(string(input))), nil)
	want := "rewrite violation at event 2: no applicable rule found " + rejected.String()
	if !errors.Is(err, monitor.ErrNoApplicableRule) || err.Error() != want {
		t.Fatalf("Rewrite error = %v, want %q", err, want)
	}
}

func TestRewriteHandlesEveryOutputBeforeAViolation(t *testing.T) {
	t.Parallel()

	m := rewritingRunnerMonitor(t)
	const accepted = 200
	var input strings.Builder
	for range accepted {
		input.Write(runnerEventLine(t, runnerEvent(runnerInputEventName, term.NewConstant("v"))))
	}
	input.Write(runnerEventLine(t, runnerEvent(runnerOutputEventName, term.NewConstant("v"))))

	// The first output is handled late, so that the rewriter has processed
	// every event and the other outputs and the violation are pending
	// together.
	outputs := 0
	err := m.Rewrite(context.Background(), io.NopCloser(strings.NewReader(input.String())), func(*monitor.TimedEvent) error {
		if outputs == 0 {
			time.Sleep(100 * time.Millisecond)
		}
		outputs++
		return nil
	})
	if !errors.Is(err, monitor.ErrNoApplicableRule) {
		t.Fatalf("Rewrite error = %v, want the violation", err)
	}
	if outputs != accepted {
		t.Fatalf("handled %d outputs, want %d", outputs, accepted)
	}
}

func TestRunPipelineSettlesAfterDownstreamViolation(t *testing.T) {
	t.Parallel()

	const eventCount = 5000
	rewriter := rewritingRunnerMonitor(t)
	main, err := monitor.NewMonitor(nil)
	if err != nil {
		t.Fatalf("NewMonitor main: %v", err)
	}

	line := runnerEventLine(t, runnerEvent(runnerInputEventName, term.NewConstant(1)))
	reader := &closeTrackingReader{Reader: strings.NewReader(strings.Repeat(string(line), eventCount))}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	violation, err := monitor.RunPipeline(ctx, rewriter, main, reader, nil)
	if err != nil || violation == nil || !errors.Is(violation.Err, monitor.ErrNoApplicableRule) {
		t.Fatalf("RunPipeline = (%v, %v), want main violation", violation, err)
	}
	if reader.closes.Load() != 1 {
		t.Fatalf("input closed %d times, want once", reader.closes.Load())
	}
}
