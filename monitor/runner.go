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
	"sync"

	"github.com/specmon/specmon/term"
)

// Run monitors the events of r and hands each consumed event to
// onConsumed. It closes r and returns the first violation, or an error.
func (m *Monitor) Run(
	ctx context.Context,
	r io.ReadCloser,
	onConsumed func(term.Term) error,
) (*ViolationInfo, error) {
	return runMonitor(ctx, m, r, false, nil, onConsumed)
}

// Rewrite processes the events of r with rewrite rules and hands each
// output event to onOutput. It closes r. A violation is returned as an
// error.
func (m *Monitor) Rewrite(
	ctx context.Context,
	r io.ReadCloser,
	onOutput func(*TimedEvent) error,
) error {
	violation, err := runMonitor(ctx, m, r, true, onOutput, nil)
	if violation != nil {
		return fmt.Errorf("rewrite violation: %w", violation.Err)
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
// r and returns the first violation of main, or an error.
func RunPipeline(
	ctx context.Context,
	rewriter *Monitor,
	main *Monitor,
	r io.ReadCloser,
	onConsumed func(term.Term) error,
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
	rewriteStreams := rewriter.ProcessEvents(runCtx, events, true)
	rewritten, rewriteConsumed, rewriteTerminal := rewriteStreams.Outputs, rewriteStreams.Consumed, rewriteStreams.Terminal
	mainStreams := main.ProcessEvents(runCtx, rewritten, false)
	mainOutput, mainConsumed, mainTerminal := mainStreams.Outputs, mainStreams.Consumed, mainStreams.Terminal
	callerDone := ctx.Done()
	var rewrittenDrain <-chan *TimedEvent

	var violation *ViolationInfo
	var ordinaryErr error
	var callerErr error
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

	for mainOutput != nil || mainConsumed != nil || mainTerminal != nil ||
		rewriteConsumed != nil || rewriteTerminal != nil || parseTerminal != nil || rewrittenDrain != nil {
		select {
		case <-callerDone:
			callerErr = ctx.Err()
			callerDone = nil
			stop()
		case _, ok := <-mainOutput:
			if !ok {
				mainOutput = nil
			}
		case event, ok := <-mainConsumed:
			if !ok {
				mainConsumed = nil
				continue
			}
			if !stopping && onConsumed != nil {
				recordError(onConsumed(event))
			}
		case _, ok := <-rewriteConsumed:
			if !ok {
				rewriteConsumed = nil
			}
		case result, ok := <-mainTerminal:
			if !ok {
				mainTerminal = nil
				rewrittenDrain = rewritten
				continue
			}
			if result.Violation != nil {
				violation = result.Violation
				stop()
			} else {
				recordError(result.Err)
			}
		case result, ok := <-rewriteTerminal:
			if !ok {
				rewriteTerminal = nil
				continue
			}
			if result.Violation != nil {
				recordError(fmt.Errorf("rewrite violation: %w", result.Violation.Err))
			} else {
				recordError(result.Err)
			}
		case err, ok := <-parseTerminal:
			if !ok {
				parseTerminal = nil
				continue
			}
			recordError(err)
		case _, ok := <-rewrittenDrain:
			if !ok {
				rewrittenDrain = nil
			}
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
	return nil, nil
}

func isExpectedShutdownError(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, net.ErrClosed)
}
