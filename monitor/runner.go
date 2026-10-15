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
	violation, err := runMonitor(ctx, m, r, true, onOutput, nil, nil)
	if violation != nil {
		return fmt.Errorf("rewrite violation at event %d: %w %s",
			violation.EventIndex, violation.Err, violation.TimedEvent.Event)
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

	start := time.Now()
	if rewriter.stats.StartTime.IsZero() {
		rewriter.stats.StartTime = start
	}
	if main.stats.StartTime.IsZero() {
		main.stats.StartTime = start
	}
	states := initialPipelineStates(rewriter, main)
	aggregateStates := states
	defer func() {
		end := time.Now()
		rewriter.stats.EndTime = end
		main.stats.EndTime = end
		updatePipelineConfigs(rewriter, main, aggregateStates)
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
				return nil, fmt.Errorf("process event %s: %w", event.Event, err)
			}
			states = advance.next
			if len(advance.next) > 0 {
				aggregateStates = advance.next
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
}

type pipelineAdvance struct {
	next     []pipelineState
	consumed []term.Term
	failure  *pipelineFailure
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

	var transitions []pipelineTransition
	var failed *pipelineFailure
	rewriteMatched := false
	for _, state := range states {
		applications, err := rewriter.processConfigEvent(state.rewrite, event.Event, key)
		if err != nil {
			return pipelineAdvance{}, err
		}
		if len(applications) == 0 {
			continue
		}
		rewriteMatched = true

		for _, application := range applications {
			outputs, err := rewriteOutputs(application.actions)
			if err != nil {
				return pipelineAdvance{}, err
			}
			mainResult, err := advanceMainConfigs(main, state.main, outputs, event.Time)
			if err != nil {
				return pipelineAdvance{}, err
			}
			if len(mainResult.configs) == 0 {
				if mainResult.failure != nil {
					failed = mainResult.failure
				}
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

	if len(transitions) == 0 {
		if !rewriteMatched {
			return pipelineAdvance{}, fmt.Errorf("rewrite violation: %w", ErrNoApplicableRule)
		}
		return pipelineAdvance{failure: failed}, nil
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

	return pipelineAdvance{next: next, consumed: consumed}, nil
}

func advanceMainConfigs(
	main *Monitor,
	configs []*Config,
	outputs []*term.Function,
	eventTime int64,
) (mainAdvance, error) {
	current := configs
	for i, output := range outputs {
		key, err := ruleKeyForTerm(output)
		if err != nil {
			return mainAdvance{}, fmt.Errorf("invalid rewritten event: %w", err)
		}
		next := data.NewHashSet[*Config]()
		for _, config := range current {
			applications, err := main.processConfigEvent(config, output, key)
			if err != nil {
				return mainAdvance{}, err
			}
			for _, application := range applications {
				next.Add(application.config)
			}
		}
		if next.Empty() {
			processed := make([]term.Term, i)
			for j := range i {
				processed[j] = outputs[j]
			}
			return mainAdvance{
				failure: &pipelineFailure{
					event:     &TimedEvent{Time: eventTime, Event: output},
					processed: processed,
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
		rewriteTerm := getRewriteTerm(action)
		if rewriteTerm == nil {
			continue
		}
		output, err := term.AsFunction(rewriteTerm)
		if err != nil {
			return nil, fmt.Errorf("rewrite action %s: %w", action, err)
		}
		outputs = append(outputs, output)
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

func updatePipelineConfigs(rewriter, main *Monitor, states []pipelineState) {
	rewriteConfigs := data.NewHashSet[*Config]()
	mainConfigs := data.NewHashSet[*Config]()
	for _, state := range states {
		rewriteConfigs.Add(state.rewrite)
		for _, mainConfig := range state.main {
			mainConfigs.Add(mainConfig)
		}
	}
	rewriter.configs = rewriteConfigs
	main.configs = mainConfigs
}

func isExpectedShutdownError(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, net.ErrClosed)
}
