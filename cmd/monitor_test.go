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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
	"github.com/spf13/cobra"
)

const (
	monitorTestEventName          = "monitorTestEvent"
	monitorTestRewrittenEventName = "monitorTestRewrittenEvent"
)

func writeMonitorInput(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write monitor input: %v", err)
	}
	return path
}

func monitorTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd
}

func TestMonitorPIDFlagAndDomain(t *testing.T) {
	monitorCmd := NewMonitorCmd()
	if flag := monitorCmd.PersistentFlags().Lookup("pid"); flag == nil {
		t.Fatal("monitor pid flag is missing")
	}
	timeoutFlag := monitorCmd.PersistentFlags().Lookup("on-violation-timeout")
	if timeoutFlag == nil || timeoutFlag.DefValue != defaultViolationHookTimeout.String() {
		t.Fatalf("monitor hook timeout default = %v, want %s", timeoutFlag, defaultViolationHookTimeout)
	}
	if flag := NewRewriteCmd().PersistentFlags().Lookup("pid"); flag != nil {
		t.Fatalf("rewrite unexpectedly exposes pid flag: %v", flag)
	}
	if flag := NewRewriteCmd().PersistentFlags().Lookup("on-violation"); flag != nil {
		t.Fatalf("rewrite unexpectedly exposes on-violation flag: %v", flag)
	}

	for _, pid := range []int{-2, -1, 0} {
		cmd := monitorTestCommand()
		cmd.Flags().Int("pid", 0, "")
		cmd.Flags().Lookup("pid").Changed = true
		config := MonitorConfig{Pid: pid}
		if err := config.RunE(cmd, []string{"unused"}); err == nil {
			t.Fatalf("MonitorConfig accepted pid %d", pid)
		}
	}
	config := MonitorConfig{OnViolationTimeout: -time.Second}
	if err := config.RunE(monitorTestCommand(), []string{"unused"}); err == nil {
		t.Fatal("MonitorConfig accepted a negative violation hook timeout")
	}
}

func TestMonitorRewriteRulesIgnoreMainRole(t *testing.T) {
	tempDir := t.TempDir()
	mainSpecPath := filepath.Join(tempDir, "main.spthy")
	rewriteSpecPath := filepath.Join(tempDir, "rewrite.spthy")
	mainSpec := `theory Main
begin

rule Server [no-decomp, role="Server", trigger=[<monitorTestRewrittenEvent(), <>>]]:
  [ ] --> [ ]

end
`
	rewriteSpec := `theory Rewrite
begin

rule Rewrite [no-decomp, trigger=[<monitorTestEvent(), <>>]]:
  [ ] --[ PPEvent(<monitorTestRewrittenEvent(), <>>) ]-> [ ]

end
`
	if err := os.WriteFile(mainSpecPath, []byte(mainSpec), 0o600); err != nil {
		t.Fatalf("write main specification: %v", err)
	}
	if err := os.WriteFile(rewriteSpecPath, []byte(rewriteSpec), 0o600); err != nil {
		t.Fatalf("write rewrite specification: %v", err)
	}

	cmd := monitorTestCommand()
	cmd.Flags().String("role", "Server", "")
	cmd.Flags().Bool("decompose", true, "")
	cmd.Flags().StringSlice("defines", nil, "")
	config := MonitorConfig{
		In:          writeMonitorInput(t, monitorEventLine(t, monitorTestEventName)),
		RewriteWith: rewriteSpecPath,
	}
	if err := config.RunE(cmd, []string{mainSpecPath}); err != nil {
		t.Fatalf("MonitorConfig.RunE with roleless rewrite rule: %v", err)
	}
}

const (
	monitorTestOtherEventName   = "monitorTestOtherEvent"
	monitorTestUnknownEventName = "monitorTestUnknownEvent"
)

// monitorEventLine returns a trace line with the event <name(), <>>.
func monitorEventLine(t *testing.T, name string) []byte {
	t.Helper()
	b, err := json.Marshal(&monitor.TimedEvent{Time: time.Now().UnixNano(), Event: monitorEvent(name)})
	if err != nil {
		t.Fatalf("marshal monitor event: %v", err)
	}
	return append(b, '\n')
}

func monitorEvent(name string) *term.Function {
	return term.NewFunction(term.PairFunctionName, []term.Term{
		term.NewFunction(name, nil),
		term.NewFunction(term.PairFunctionName, nil),
	})
}

// writeMonitorSpec writes a theory with the given rules.
func writeMonitorSpec(t *testing.T, rules string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.spthy")
	if err := os.WriteFile(path, []byte("theory MonitorTest\nbegin\n\n"+rules+"\nend\n"), 0o600); err != nil {
		t.Fatalf("write specification: %v", err)
	}
	return path
}

// acceptingSpec accepts the events monitorTestEvent and nothing else.
const acceptingSpec = `rule Accept [trigger=[<monitorTestEvent(), r>]]:
  [ ] --> [ ]
`

func TestMonitorViolationErrorNamesEvent(t *testing.T) {
	specPath := writeMonitorSpec(t, acceptingSpec)
	trace := append(monitorEventLine(t, monitorTestEventName), monitorEventLine(t, monitorTestOtherEventName)...)
	want := "at event 2: no applicable rule found " + monitorEvent(monitorTestOtherEventName).String()

	config := MonitorConfig{In: writeMonitorInput(t, trace)}
	err := config.RunE(monitorTestCommand(), []string{specPath})
	if !errors.Is(err, monitor.ErrNoApplicableRule) || err.Error() != "monitor violation "+want {
		t.Fatalf("RunE error = %v, want %q", err, "monitor violation "+want)
	}

	config = MonitorConfig{In: writeMonitorInput(t, nil), PreTrace: writeMonitorInput(t, trace)}
	err = config.RunE(monitorTestCommand(), []string{specPath})
	if !errors.Is(err, monitor.ErrNoApplicableRule) || err.Error() != "monitor pre-trace violation "+want {
		t.Fatalf("RunE error = %v, want %q", err, "monitor pre-trace violation "+want)
	}
}

func TestMonitorOpensInputBeforePreTrace(t *testing.T) {
	specPath := writeMonitorSpec(t, acceptingSpec)
	config := MonitorConfig{
		In:       filepath.Join(t.TempDir(), "missing.jsonl"),
		PreTrace: writeMonitorInput(t, monitorEventLine(t, monitorTestOtherEventName)),
	}
	err := config.RunE(monitorTestCommand(), []string{specPath})
	if err == nil || !strings.Contains(err.Error(), "cannot open input") {
		t.Fatalf("RunE error = %v, want the input opened before the pre-trace runs", err)
	}
}

func TestMonitorPreTraceViolationRunsReaction(t *testing.T) {
	payloadPath := filepath.Join(t.TempDir(), "payload.json")
	t.Setenv(testPayloadPathEnv, payloadPath)
	var kills atomic.Int32
	config := MonitorConfig{
		In:                 writeMonitorInput(t, nil),
		PreTrace:           writeMonitorInput(t, append(monitorEventLine(t, monitorTestEventName), monitorEventLine(t, monitorTestOtherEventName)...)),
		Pid:                123,
		OnViolation:        writeViolationHook(t, "cat > \"$"+testPayloadPathEnv+"\"\n"),
		OnViolationTimeout: testHookTimeout,
		terminateProcess: func(int) error {
			kills.Add(1)
			return nil
		},
	}
	err := config.RunE(monitorTestCommand(), []string{writeMonitorSpec(t, acceptingSpec)})
	if !errors.Is(err, monitor.ErrNoApplicableRule) || !strings.HasPrefix(err.Error(), "monitor pre-trace violation at event 2:") {
		t.Fatalf("RunE error = %v, want the pre-trace violation at event 2", err)
	}
	payload := readMonitorHookPayload(t, payloadPath)
	if payload.EventIndex != 2 || kills.Load() != 1 {
		t.Fatalf("hook payload event_index = %d, kills = %d; want 2 and 1", payload.EventIndex, kills.Load())
	}
}

// TestMonitorRewriteViolationCountsRewrittenEvents checks that the index of
// a violation with --rewrite-with counts the events that the rewriter
// emits, not the raw events.
func TestMonitorRewriteViolationCountsRewrittenEvents(t *testing.T) {
	payloadPath := filepath.Join(t.TempDir(), "payload.json")
	t.Setenv(testPayloadPathEnv, payloadPath)
	rewritePath := filepath.Join(t.TempDir(), "rewrite.spthy")
	rewrite := `theory MonitorRewrite
begin

rule Twice [trigger=[<monitorTestEvent(), r>]]:
  [ ] --[ PPEvent(<monitorTestRewrittenEvent(), r>), PPEvent(<monitorTestRewrittenEvent(), r>) ]-> [ ]

rule Unknown [trigger=[<monitorTestOtherEvent(), r>]]:
  [ ] --[ PPEvent(<monitorTestUnknownEvent(), r>) ]-> [ ]

end
`
	if err := os.WriteFile(rewritePath, []byte(rewrite), 0o600); err != nil {
		t.Fatalf("write rewrite theory: %v", err)
	}
	config := MonitorConfig{
		In:                 writeMonitorInput(t, append(monitorEventLine(t, monitorTestEventName), monitorEventLine(t, monitorTestOtherEventName)...)),
		RewriteWith:        rewritePath,
		OnViolation:        writeViolationHook(t, "cat > \"$"+testPayloadPathEnv+"\"\n"),
		OnViolationTimeout: testHookTimeout,
	}
	spec := writeMonitorSpec(t, `rule Accept [trigger=[<monitorTestRewrittenEvent(), r>]]:
  [ ] --> [ ]
`)
	err := config.RunE(monitorTestCommand(), []string{spec})
	want := "monitor violation at event 3: no applicable rule found " + monitorEvent(monitorTestUnknownEventName).String()
	if !errors.Is(err, monitor.ErrNoApplicableRule) || err.Error() != want {
		t.Fatalf("RunE error = %v, want %q", err, want)
	}
	if payload := readMonitorHookPayload(t, payloadPath); payload.EventIndex != 3 {
		t.Fatalf("hook payload event_index = %d, want 3", payload.EventIndex)
	}
}

func readMonitorHookPayload(t *testing.T, path string) violationHookPayload {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hook payload: %v", err)
	}
	if !bytes.HasSuffix(b, []byte("\n")) {
		t.Fatalf("hook payload is not newline terminated: %q", b)
	}
	var payload violationHookPayload
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatalf("unmarshal hook payload: %v", err)
	}
	return payload
}
