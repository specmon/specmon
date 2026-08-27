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

func monitorTestEventLine(t *testing.T) []byte {
	t.Helper()
	event := &monitor.TimedEvent{
		Time: time.Now().UnixNano(),
		Event: term.NewFunction(term.PairFunctionName, []term.Term{
			term.NewFunction(monitorTestEventName, nil),
			term.NewFunction(term.PairFunctionName, nil),
		}),
	}
	b, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal monitor event: %v", err)
	}
	return append(b, '\n')
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
	var help bytes.Buffer
	monitorCmd.SetOut(&help)
	monitorCmd.SetArgs([]string{"--help"})
	if err := monitorCmd.Execute(); err != nil {
		t.Fatalf("render monitor help: %v", err)
	}
	for _, line := range strings.Split(help.String(), "\n") {
		if strings.Contains(line, "--pid int") && strings.Contains(line, "default") {
			t.Fatalf("monitor pid help exposes a default: %q", line)
		}
	}
	if flag := NewRewriteCmd().PersistentFlags().Lookup("pid"); flag != nil {
		t.Fatalf("rewrite unexpectedly exposes pid flag: %v", flag)
	}

	missingValueCmd := NewMonitorCmd()
	missingValueCmd.SilenceErrors = true
	missingValueCmd.SilenceUsage = true
	missingValueCmd.SetArgs([]string{"--pid"})
	if err := missingValueCmd.Execute(); err == nil || !strings.Contains(err.Error(), "flag needs an argument") {
		t.Fatalf("monitor --pid error = %v, want missing argument error", err)
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
}

func TestMonitorTerminatesPIDOnlyForViolations(t *testing.T) {
	specPath := filepath.Join("..", "testdata", "translation", "no_decomposition", "input.spthy")
	for _, test := range []struct {
		name          string
		input         []byte
		wantKills     int32
		wantViolation bool
	}{
		{
			name:          "violation",
			input:         monitorTestEventLine(t),
			wantKills:     1,
			wantViolation: true,
		},
		{
			name:  "parse error",
			input: []byte("not json\n"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var kills atomic.Int32
			config := MonitorConfig{
				In:  writeMonitorInput(t, test.input),
				Pid: 123,
				terminateProcess: func(pid int) error {
					if pid != 123 {
						t.Fatalf("terminate process called with pid %d", pid)
					}
					kills.Add(1)
					return nil
				},
			}

			err := config.RunE(monitorTestCommand(), []string{specPath})
			if err == nil {
				t.Fatal("MonitorConfig.RunE returned nil")
			}
			if test.wantViolation && !errors.Is(err, monitor.ErrNoApplicableRule) {
				t.Fatalf("RunE error = %v, want ErrNoApplicableRule", err)
			}
			if got := kills.Load(); got != test.wantKills {
				t.Fatalf("terminate process called %d times, want %d", got, test.wantKills)
			}
		})
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
		In:          writeMonitorInput(t, monitorTestEventLine(t)),
		RewriteWith: rewriteSpecPath,
	}
	if err := config.RunE(cmd, []string{mainSpecPath}); err != nil {
		t.Fatalf("MonitorConfig.RunE with roleless rewrite rule: %v", err)
	}
}
