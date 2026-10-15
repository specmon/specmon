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
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// Run monitors the events of r and hands each consumed event to
// onConsumed. It closes r and returns the first violation, or an error.
// Optional onIdle callbacks run synchronously whenever no consumed events
// are queued, before waiting for more. A callback error stops the run.
func (m *Monitor) Run(
	ctx context.Context,
	r io.ReadCloser,
	onConsumed func(term.Term) error,
	onIdle ...func() error,
) (*ViolationInfo, error) {
	return runMonitor(ctx, m, r, false, nil, onConsumed, onIdle)
}

// Rewrite processes the events of r with rewrite rules and hands each
// output event to onOutput. It closes r. A violation is returned as an
// error that names the index and the term of the rejected event.
func (m *Monitor) Rewrite(
	ctx context.Context,
	r io.ReadCloser,
	onOutput func(*TimedEvent) error,
) error {
	m.site.monitor = FailureMonitorRewrite
	violation, err := runMonitor(ctx, m, r, true, onOutput, nil, nil)
	if violation != nil {
		return fmt.Errorf("rewrite violation at event %d: %w %s", violation.EventIndex, violation.Err, violation.TimedEvent.Event)
	}
	return err
}

func runMonitor(
	ctx context.Context,
	m *Monitor,
	r io.ReadCloser,
	rewrite bool,
	onOutput func(*TimedEvent) error,
	onConsumed func(term.Term) error,
	onIdle []func() error,
) (*ViolationInfo, error) {
	if r == nil {
		return nil, errors.New("input reader is nil")
	}

	runCtx, cancel := context.WithCancel(ctx)
	var stopOnce sync.Once
	stopping := false
	stop := func() {
		stopOnce.Do(func() {
			stopping = true
			cancel()
			_ = r.Close()
		})
	}
	defer stop()

	events, parseTerminal := ParseEvents(runCtx, r)
	streams := m.ProcessEvents(runCtx, events, rewrite)
	outputs := streams.Outputs
	consumed := streams.Consumed
	processTerminal := streams.Terminal
	callerDone := ctx.Done()

	var violation *ViolationInfo
	var ordinaryErr error
	var callerErr error
	// parseErr is a failure to read or parse the input. The events parsed
	// before it are still processed, so that a violation among them is
	// reported instead of the parse error.
	var parseErr error
	recordError := func(err error) {
		if err == nil {
			return
		}
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			if callerErr == nil {
				callerErr = ctx.Err()
			}
			stop()
			return
		}
		if stopping && isExpectedShutdownError(err) {
			return
		}
		if ordinaryErr == nil {
			ordinaryErr = err
		}
		stop()
	}

	// Once stopping, the loop does not wait for the parser: a read from a
	// pipe or terminal does not return when the input is closed, and the
	// parser ends on its own when its read returns.
	for outputs != nil || consumed != nil || processTerminal != nil || (parseTerminal != nil && !stopping) {
		if len(onIdle) > 0 && len(consumed) == 0 {
			recordError(notifyIdle(onIdle))
		}
		// The result of processing is read once every output and consumed
		// event is handled. The processor closes both before it sends its
		// result, so that the events before a violation are not dropped.
		terminal := processTerminal
		if outputs != nil || consumed != nil {
			terminal = nil
		}
		select {
		case <-callerDone:
			callerErr = ctx.Err()
			callerDone = nil
			stop()
		case output, ok := <-outputs:
			if !ok {
				outputs = nil
				continue
			}
			if !stopping && onOutput != nil {
				recordError(onOutput(output))
			}
		case event, ok := <-consumed:
			if !ok {
				consumed = nil
				continue
			}
			if !stopping && onConsumed != nil {
				recordError(onConsumed(event))
			}
		case result := <-terminal:
			// The processor and the parser each send one result.
			processTerminal = nil
			if result.Violation != nil {
				violation = result.Violation
				stop()
			} else {
				recordError(result.Err)
			}
		case err := <-parseTerminal:
			parseTerminal = nil
			if err != nil && !stopping && (ctx.Err() == nil || !errors.Is(err, ctx.Err())) {
				parseErr = err
				continue
			}
			recordError(err)
		}
	}

	if violation != nil {
		return violation, nil
	}
	if ordinaryErr != nil {
		return nil, ordinaryErr
	}
	if callerErr != nil {
		return nil, callerErr
	}
	return nil, parseErr
}

// RunPipeline rewrites the events of r with rewriter and monitors the
// outputs with main, handing each consumed event to onConsumed. It closes
// r and returns the first violation of main, or an error. Optional onIdle
// callbacks run synchronously when no input events are queued, before
// waiting for more. A callback error stops the run.
//
// Each rewrite configuration stays paired with the core configurations
// that its outputs led to, but only within one call. A later call starts
// from every combination of the configurations that the two monitors hold,
// so an input split over two calls may be accepted where the same input in
// one call is rejected.
func RunPipeline(
	ctx context.Context,
	rewriter *Monitor,
	main *Monitor,
	r io.ReadCloser,
	onConsumed func(term.Term) error,
	onIdle ...func() error,
) (*ViolationInfo, error) {
	if r == nil {
		return nil, errors.New("input reader is nil")
	}
	if rewriter == nil || main == nil {
		return nil, errors.New("pipeline monitor is nil")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		_ = r.Close()
	}()

	// One log keeps the records of both monitors, so that the records of
	// every alternative of a raw event stay together until it is decided.
	rewriter.site.monitor = FailureMonitorRewrite
	rewriter.failures = main.failures

	start := time.Now()
	if rewriter.stats.StartTime.IsZero() {
		rewriter.stats.StartTime = start
	}
	if main.stats.StartTime.IsZero() {
		main.stats.StartTime = start
	}
	// states are the live pipeline states. After an event without a
	// surviving branch they are empty, and lastStates, the last states
	// that were not, remain for the diagnostics.
	states := initialPipelineStates(rewriter, main)
	lastStates := states
	defer func() {
		end := time.Now()
		rewriter.stats.EndTime = end
		main.stats.EndTime = end
		updatePipelineConfigs(rewriter, main, states, lastStates)
		rewriter.logFinalConfigs()
		main.logFinalConfigs()
	}()

	events, parseTerminal := ParseEvents(runCtx, r)

	for events != nil || parseTerminal != nil {
		if len(onIdle) > 0 && len(events) == 0 {
			if err := notifyIdle(onIdle); err != nil {
				return nil, err
			}
		}
		// The parse result is read once every parsed event is processed, so
		// that a violation before a parse error is reported. The parser
		// closes the events before it closes its buffered result.
		terminal := parseTerminal
		if events != nil {
			terminal = nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if event == nil || event.Event == nil {
				return nil, errors.New("event or event term is nil")
			}
			receivedLatency := time.Since(time.Unix(0, event.Time))
			rewriter.stats.LatenciesReceived = append(
				rewriter.stats.LatenciesReceived,
				receivedLatency,
			)
			advance, err := advancePipeline(rewriter, main, states, event)
			if err != nil {
				// A rejection on the rewrite side leaves no branch. It is
				// reported as an error, without a violation.
				if errors.Is(err, ErrNoApplicableRule) {
					states = nil
				}
				return nil, fmt.Errorf("process event %s: %w", event.Event, err)
			}
			states = advance.next
			if len(advance.next) > 0 {
				lastStates = advance.next
			}
			rewriter.stats.LatenciesProcessed = append(
				rewriter.stats.LatenciesProcessed,
				time.Since(time.Unix(0, event.Time)),
			)
			consumed := advance.consumed
			if advance.failure != nil {
				consumed = advance.failure.processed
			}
			if err := recordPipelineOutputs(main, event.Time, consumed, receivedLatency, onConsumed); err != nil {
				return nil, err
			}
			if advance.failure != nil {
				main.stats.LatenciesReceived = append(main.stats.LatenciesReceived, receivedLatency)
				end := time.Now()
				return &ViolationInfo{
					Err:        ErrNoApplicableRule,
					ErrorKind:  ViolationKindNoApplicableRule,
					TimedEvent: cloneTimedEvent(advance.failure.event),
					EventIndex: len(main.stats.LatenciesReceived),
					Stats:      main.stats.Summary(end),
					Failures:   main.failures.report(),
				}, nil
			}
		case err := <-terminal:
			parseTerminal = nil
			if err != nil {
				return nil, err
			}
		}
	}

	return nil, nil
}

// notifyIdle lets a consumer publish pending output before the runner waits.
func notifyIdle(callbacks []func() error) error {
	for _, callback := range callbacks {
		if callback != nil {
			if err := callback(); err != nil {
				return err
			}
		}
	}
	return nil
}

// pipelineState associates one rewrite configuration with the downstream
// configurations that have consumed exactly the outputs from that rewrite path.
type pipelineState struct {
	rewrite *Config
	main    []*Config
}

type pipelineTransition struct {
	state   pipelineState
	outputs []*term.Function
}

type pipelineFailure struct {
	event     *TimedEvent
	processed []term.Term
	// configs are the core configurations that tried the event, and
	// position identifies it among the outputs of the raw event.
	configs  []*Config
	position RewritePosition
}

type pipelineAdvance struct {
	next     []pipelineState
	consumed []term.Term
	// failure is set when the main monitor rejects every rewrite
	// alternative.
	failure *pipelineFailure
}

type mainAdvance struct {
	configs []*Config
	failure *pipelineFailure
}

func initialPipelineStates(rewriter, main *Monitor) []pipelineState {
	mainConfigs := main.configs.Values()
	states := make([]pipelineState, 0, rewriter.configs.Size())
	for _, rewriteConfig := range rewriter.configs.Values() {
		states = append(states, pipelineState{rewrite: rewriteConfig, main: mainConfigs})
	}
	return states
}

func advancePipeline(
	rewriter *Monitor,
	main *Monitor,
	states []pipelineState,
	event *TimedEvent,
) (pipelineAdvance, error) {
	key, err := ruleKeyForTerm(event.Event)
	if err != nil {
		return pipelineAdvance{}, fmt.Errorf("invalid event: %w", err)
	}
	rewriter.beginEvent()
	// The core monitor counts the rewritten events. Each alternative of
	// the raw event counts its outputs from the same base.
	base := main.site.event
	alternative := 0

	var transitions []pipelineTransition
	var failures []*pipelineFailure
	for _, state := range states {
		applications, err := rewriter.processConfigEvent(state.rewrite, event.Event, key)
		if err != nil {
			return pipelineAdvance{}, err
		}
		for _, application := range applications {
			outputs, err := rewriteOutputs(application.actions)
			if err != nil {
				return pipelineAdvance{}, err
			}
			alternative++
			position := RewritePosition{RawEvent: rewriter.site.event, Alternative: alternative}
			mainResult, err := advanceMainConfigs(main, state.main, outputs, event.Time, base, position)
			if err != nil {
				return pipelineAdvance{}, err
			}
			// An alternative whose outputs the core monitor consumed, or
			// that emitted none, continues. The others failed.
			if mainResult.failure != nil {
				failures = append(failures, mainResult.failure)
				continue
			}
			transitions = append(transitions, pipelineTransition{
				state: pipelineState{
					rewrite: application.config,
					main:    mainResult.configs,
				},
				outputs: outputs,
			})
		}
	}

	// Without a surviving branch, the rewriter rejects the event if none of
	// its candidates succeeded, and the core monitor otherwise. Every
	// rewrite alternative gives a transition or a failure, so without
	// either no rewrite candidate succeeded. The allowed events of the side
	// that rejects are logged, as a single monitor does, with the rewrite
	// position of each failed alternative.
	if len(transitions) == 0 {
		if len(failures) == 0 {
			rewriteConfigs := make([]*Config, len(states))
			for i, state := range states {
				rewriteConfigs[i] = state.rewrite
			}
			rewriter.logAllowedEvents(rewriteConfigs, func(i int) string {
				return fmt.Sprintf("allowed raw events in rewrite configuration %d", i)
			})
			return pipelineAdvance{}, fmt.Errorf("rewrite violation: %w", ErrNoApplicableRule)
		}
		for _, failure := range failures {
			main.logAllowedEvents(failure.configs, func(i int) string {
				return fmt.Sprintf("allowed events in core configuration %d (raw event %d, alternative %d, position %d)",
					i, failure.position.RawEvent, failure.position.Alternative, failure.position.Position)
			})
		}
		// As before, the violation names the failure of the last alternative.
		return pipelineAdvance{failure: failures[len(failures)-1]}, nil
	}

	transitions = dedupePipelineTransitions(transitions)
	next := make([]pipelineState, len(transitions))
	var consumed []term.Term
	var reportedOutputs [][]*term.Function
	for i, transition := range transitions {
		next[i] = transition.state
		if slices.ContainsFunc(reportedOutputs, func(reported []*term.Function) bool {
			return outputsEqual(reported, transition.outputs)
		}) {
			continue
		}
		reportedOutputs = append(reportedOutputs, transition.outputs)
		for _, output := range transition.outputs {
			consumed = append(consumed, output)
		}
	}
	main.site.event = base + len(consumed)
	// The next event tries the branches in the order of their rewrite
	// configuration hashes, as a single monitor tries its configurations,
	// and then of the hashes of their core configurations.
	slices.SortFunc(next, func(a, b pipelineState) int {
		if c := cmp.Compare(a.rewrite.Hash(), b.rewrite.Hash()); c != 0 {
			return c
		}
		return slices.CompareFunc(a.main, b.main, func(x, y *Config) int { return cmp.Compare(x.Hash(), y.Hash()) })
	})

	return pipelineAdvance{next: next, consumed: consumed}, nil
}

// advanceMainConfigs lets the core monitor consume the outputs of one
// rewrite alternative. Its records count the outputs from base and carry
// position with the index of each output.
func advanceMainConfigs(
	main *Monitor,
	configs []*Config,
	outputs []*term.Function,
	eventTime int64,
	base int,
	position RewritePosition,
) (mainAdvance, error) {
	current := configs
	for i, output := range outputs {
		main.site.event = base + i + 1
		main.site.rewrite = position
		main.site.rewrite.Position = i + 1
		next := data.NewHashSet[*Config]()
		// Invalid emitted heads end only this rewrite alternative.
		key, err := ruleKeyForTerm(output)
		if err == nil {
			err = checkRewriteEvent(output)
		}
		if err != nil {
			for _, config := range current {
				main.site.branch = config
				main.recordFailure(FailureNoCandidate, "", fmt.Sprintf("no rule candidate consumes the event: %v", err), nil)
			}
		} else {
			for _, config := range current {
				applications, err := main.processConfigEvent(config, output, key)
				if err != nil {
					return mainAdvance{}, err
				}
				for _, application := range applications {
					next.Add(application.config)
				}
			}
		}
		if next.Empty() {
			processed := make([]term.Term, i)
			for j, previous := range outputs[:i] {
				processed[j] = previous
			}
			return mainAdvance{
				failure: &pipelineFailure{
					event:     &TimedEvent{Time: eventTime, Event: output},
					processed: processed,
					configs:   current,
					position:  main.site.rewrite,
				},
			}, nil
		}
		current = next.Values()
	}
	return mainAdvance{configs: current}, nil
}

func recordPipelineOutputs(
	main *Monitor,
	eventTime int64,
	outputs []term.Term,
	receivedLatency time.Duration,
	onConsumed func(term.Term) error,
) error {
	for _, output := range outputs {
		main.stats.LatenciesReceived = append(
			main.stats.LatenciesReceived,
			receivedLatency,
		)
		main.stats.LatenciesProcessed = append(
			main.stats.LatenciesProcessed,
			time.Since(time.Unix(0, eventTime)),
		)
		if onConsumed != nil {
			if err := onConsumed(output); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteOutputs(actions []*rule.Fact) ([]*term.Function, error) {
	var outputs []*term.Function
	for _, action := range actions {
		rewriteTerm := action.RewriteTerm()
		if rewriteTerm == nil {
			continue
		}
		// Loading ensures that an output is a pair. Anything else is a
		// broken invariant.
		if event, result := term.SplitPair(rewriteTerm); event == nil || result == nil {
			return nil, fmt.Errorf("rewrite output %s is not a pair <event, result>", rewriteTerm)
		}
		outputs = append(outputs, term.Must(term.AsFunction(rewriteTerm)))
	}
	return outputs, nil
}

func dedupePipelineTransitions(transitions []pipelineTransition) []pipelineTransition {
	unique := transitions[:0]
	for _, transition := range transitions {
		if !slices.ContainsFunc(unique, func(existing pipelineTransition) bool {
			return existing.state.rewrite.Hash() == transition.state.rewrite.Hash() &&
				configSetsEqual(existing.state.main, transition.state.main) &&
				outputsEqual(existing.outputs, transition.outputs)
		}) {
			unique = append(unique, transition)
		}
	}
	return unique
}

func configSetsEqual(left, right []*Config) bool {
	if len(left) != len(right) {
		return false
	}
	for _, leftConfig := range left {
		if !slices.ContainsFunc(right, func(rightConfig *Config) bool { return rightConfig.Hash() == leftConfig.Hash() }) {
			return false
		}
	}
	return true
}

// outputsEqual compares emitted events without discarding constant kinds.
// Term.Equal intentionally equates constants with the same bytes, but their
// kinds remain visible in JSON and can change later built-in evaluation.
func outputsEqual(left, right []*term.Function) bool {
	return slices.EqualFunc(left, right, func(l, r *term.Function) bool { return term.EqualWithKind(l, r) })
}

// updatePipelineConfigs makes the configurations of states live in both
// monitors. If states is empty because an event was rejected, lastStates
// are kept for the diagnostics.
func updatePipelineConfigs(rewriter, main *Monitor, states, lastStates []pipelineState) {
	rewriter.configs, main.configs = pipelineConfigs(states)
	if len(states) == 0 && len(lastStates) > 0 {
		rewriter.rejected, main.rejected = pipelineConfigs(lastStates)
	}
}

func pipelineConfigs(states []pipelineState) (rewrite, main *data.HashSet[*Config]) {
	rewrite = data.NewHashSet[*Config]()
	main = data.NewHashSet[*Config]()
	for _, state := range states {
		rewrite.Add(state.rewrite)
		for _, mainConfig := range state.main {
			main.Add(mainConfig)
		}
	}
	return rewrite, main
}

func isExpectedShutdownError(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, net.ErrClosed)
}
