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

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/specmon/specmon/monitor"
)

var errOutputTestWrite = errors.New("test output failure")

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type failingWriter struct{}

func (w *failingWriter) Write([]byte) (int, error) {
	return 0, errOutputTestWrite
}

func consumedOutputLine(index int) string {
	return fmt.Sprintf("  %4d: %.120s\n", index, monitorEvent(monitorTestEventName))
}

type recordingWriter struct {
	writes []string
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

func TestMonitorWritesEveryConsumedEventInOrder(t *testing.T) {
	const events = 3000
	var out recordingWriter
	cmd := monitorTestCommand()
	cmd.SetOut(&out)
	config := MonitorConfig{In: writeMonitorInput(t, bytes.Repeat(monitorEventLine(t, monitorTestEventName), events))}
	if err := config.RunE(cmd, []string{writeMonitorSpec(t, acceptingSpec)}); err != nil {
		t.Fatalf("RunE: %v", err)
	}
	var want strings.Builder
	for i := range events {
		want.WriteString(consumedOutputLine(i + 1))
	}
	if got := strings.Join(out.writes[:len(out.writes)-1], ""); got != want.String() {
		t.Fatalf("consumed-event output differs from the ordered sequence")
	}
	if stats := out.writes[len(out.writes)-1]; !strings.HasPrefix(stats, "{") || strings.Count(stats, "\n") != 1 {
		t.Fatalf("statistics write = %q", stats)
	}
}

func TestMonitorConsumedOutputAppearsWhileInputStalls(t *testing.T) {
	for _, test := range []struct {
		name     string
		preTrace bool
		rewrite  bool
		burst    bool
	}{
		{name: "input"},
		{name: "pre-trace", preTrace: true},
		{name: "rewrite pipeline", rewrite: true},
		{name: "backlogged input", burst: true},
		{name: "backlogged rewrite pipeline", rewrite: true, burst: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fifo := filepath.Join(t.TempDir(), "events")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatalf("create FIFO: %v", err)
			}
			var out syncBuffer
			cmd := monitorTestCommand()
			cmd.SetOut(&out)
			config := MonitorConfig{In: fifo}
			if test.preTrace {
				config = MonitorConfig{In: writeMonitorInput(t, nil), PreTrace: fifo}
			}
			eventName := monitorTestEventName
			if test.rewrite {
				eventName = monitorTestOtherEventName
				config.RewriteWith = writeMonitorSpec(t, `rule Rewrite [no-decomp, trigger=[<monitorTestOtherEvent(), <>>]]:
  [ ] --[ PPEvent(<monitorTestEvent(), <>>) ]-> [ ]
`)
			}
			spec := writeMonitorSpec(t, acceptingSpec)
			done := make(chan error, 1)
			go func() {
				done <- config.RunE(cmd, []string{spec})
			}()

			writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
			if err != nil {
				t.Fatalf("open FIFO: %v", err)
			}
			defer writer.Close()
			var want strings.Builder
			perWrite := 1
			if test.burst {
				perWrite = 3000
			}
			for i := 1; i <= 2; i++ {
				if _, err := writer.Write(bytes.Repeat(monitorEventLine(t, eventName), perWrite)); err != nil {
					t.Fatalf("write event: %v", err)
				}
				for j := range perWrite {
					want.WriteString(consumedOutputLine((i-1)*perWrite + j + 1))
				}
				deadline := time.Now().Add(5 * time.Second)
				for out.String() != want.String() {
					if time.Now().After(deadline) {
						t.Fatalf("output while input remains open = %q, want %q", out.String(), want.String())
					}
					time.Sleep(time.Millisecond)
				}
			}

			if err := writer.Close(); err != nil {
				t.Fatalf("close input: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatalf("RunE: %v", err)
			}
		})
	}
}

func TestMonitorConsumedOutputPrecedesStatisticsAndHook(t *testing.T) {
	input := append(monitorEventLine(t, monitorTestEventName), monitorEventLine(t, monitorTestOtherEventName)...)
	pipelineInput := append(monitorEventLine(t, monitorTestOtherEventName), monitorEventLine(t, monitorTestRewrittenEventName)...)
	rewrite := writeMonitorSpec(t, `rule Accept [no-decomp, trigger=[<monitorTestOtherEvent(), <>>]]:
  [ ] --[ PPEvent(<monitorTestEvent(), <>>) ]-> [ ]
rule Reject [no-decomp, trigger=[<monitorTestRewrittenEvent(), <>>]]:
  [ ] --[ PPEvent(<monitorTestOtherEvent(), <>>) ]-> [ ]
`)
	hook := writeViolationHook(t, "cat > /dev/null\nprintf 'hook\\n'\n")
	for _, test := range []struct {
		name   string
		config MonitorConfig
	}{
		{"input", MonitorConfig{In: writeMonitorInput(t, input)}},
		{"pre-trace", MonitorConfig{In: writeMonitorInput(t, nil), PreTrace: writeMonitorInput(t, input)}},
		{"rewrite pipeline", MonitorConfig{In: writeMonitorInput(t, pipelineInput), RewriteWith: rewrite}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Both streams share one buffer, so their order is visible.
			var out syncBuffer
			cmd := monitorTestCommand()
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			config := test.config
			config.OnViolation = hook
			config.OnViolationTimeout = testHookTimeout
			if err := config.RunE(cmd, []string{writeMonitorSpec(t, acceptingSpec)}); !errors.Is(err, monitor.ErrNoApplicableRule) {
				t.Fatalf("RunE error = %v, want ErrNoApplicableRule", err)
			}

			lines := strings.Split(out.String(), "\n")
			if len(lines) != 4 || lines[0]+"\n" != consumedOutputLine(1) ||
				!strings.HasPrefix(lines[1], "{") || lines[2] != "hook" || lines[3] != "" {
				t.Fatalf("output order = %q", out.String())
			}
		})
	}
}

// TestMonitorConsumedOutputPrecedesSignalMessage checks that the consumed
// events are written before the message about a signal for ordinary,
// pre-trace and rewrite-pipeline input.
func TestMonitorConsumedOutputPrecedesSignalMessage(t *testing.T) {
	for _, mode := range []string{"input", "pre-trace", "rewrite pipeline"} {
		t.Run(mode, func(t *testing.T) {
			fifo := filepath.Join(t.TempDir(), "events")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatalf("create FIFO: %v", err)
			}
			config := MonitorConfig{In: fifo}
			if mode == "pre-trace" {
				config = MonitorConfig{In: writeMonitorInput(t, nil), PreTrace: fifo}
			}
			eventName := monitorTestEventName
			if mode == "rewrite pipeline" {
				eventName = monitorTestOtherEventName
				config.RewriteWith = writeMonitorSpec(t, `rule Rewrite [no-decomp, trigger=[<monitorTestOtherEvent(), <>>]]:
  [ ] --[ PPEvent(<monitorTestEvent(), <>>) ]-> [ ]
`)
			}
			// Both streams share one buffer, so their order is visible.
			var out syncBuffer
			cmd := monitorTestCommand()
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			done := make(chan error, 1)
			go func() {
				done <- config.RunE(cmd, []string{writeMonitorSpec(t, acceptingSpec)})
			}()

			// The FIFO opens once the monitor opens it, after it began
			// to handle signals.
			events, err := os.OpenFile(fifo, os.O_WRONLY, 0)
			if err != nil {
				t.Fatalf("open FIFO: %v", err)
			}
			defer events.Close()
			if _, err := events.Write(monitorEventLine(t, eventName)); err != nil {
				t.Fatalf("write event: %v", err)
			}
			// Wait for the consumed event before interrupting the input.
			deadline := time.Now().Add(time.Second)
			for !strings.Contains(out.String(), consumedOutputLine(1)) {
				if time.Now().After(deadline) {
					t.Fatalf("consumed event was not written: %q", out.String())
				}
				time.Sleep(time.Millisecond)
			}
			if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
				t.Fatalf("send signal: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatalf("RunE: %v", err)
			}

			_, after, found := strings.Cut(out.String(), "signal received, exiting\n")
			if !found || strings.Contains(after, consumedOutputLine(1)) {
				t.Fatalf("output = %q, want the consumed event before the signal message", out.String())
			}
		})
	}
}

func TestMonitorConsumedOutputWriteErrorPropagates(t *testing.T) {
	for _, mode := range []string{"input", "pre-trace", "rewrite pipeline"} {
		t.Run(mode, func(t *testing.T) {
			cmd := monitorTestCommand()
			cmd.SetOut(&failingWriter{})
			eventName := monitorTestEventName
			if mode == "rewrite pipeline" {
				eventName = monitorTestOtherEventName
			}
			input := writeMonitorInput(t, monitorEventLine(t, eventName))
			config := MonitorConfig{In: input}
			if mode == "pre-trace" {
				config = MonitorConfig{In: writeMonitorInput(t, nil), PreTrace: input}
			}
			if mode == "rewrite pipeline" {
				config.RewriteWith = writeMonitorSpec(t, `rule Rewrite [no-decomp, trigger=[<monitorTestOtherEvent(), <>>]]:
  [ ] --[ PPEvent(<monitorTestEvent(), <>>) ]-> [ ]
`)
			}
			err := config.RunE(cmd, []string{writeMonitorSpec(t, acceptingSpec)})
			if !errors.Is(err, errOutputTestWrite) || !strings.Contains(err.Error(), "write consumed event") {
				t.Fatalf("RunE error = %v, want a consumed event write error", err)
			}
		})
	}
}

func TestMonitorQuietWritesNoConsumedEvents(t *testing.T) {
	var out syncBuffer
	cmd := monitorTestCommand()
	cmd.SetOut(&out)
	cmd.Flags().Bool("quiet", true, "")
	config := MonitorConfig{In: writeMonitorInput(t, monitorEventLine(t, monitorTestEventName))}
	if err := config.RunE(cmd, []string{writeMonitorSpec(t, acceptingSpec)}); err != nil {
		t.Fatalf("RunE: %v", err)
	}
	if got := out.String(); !strings.HasPrefix(got, "{") || strings.Count(got, "\n") != 1 {
		t.Fatalf("quiet output = %q, want only the statistics line", got)
	}
}
