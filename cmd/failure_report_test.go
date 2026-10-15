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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/specmon/specmon/monitor"
)

func testFailureReport() monitor.FailureReport {
	return monitor.FailureReport{
		Final: []monitor.FailureRecord{
			{
				Monitor: monitor.FailureMonitorCore, Event: 7,
				Rewrite: &monitor.RewritePosition{RawEvent: 3, Alternative: 2, Position: 1},
				Rule:    "Check", Category: monitor.FailureRestriction, Message: "restriction violated: Eq('1', '2')",
				Branch: 0x2a, Cause: monitor.ErrRestrictionViolated,
			},
			{
				Monitor: monitor.FailureMonitorCore, Event: 7, Category: monitor.FailureNoCandidate,
				Message: "no rule candidate consumes the event", Branch: 0xbeef,
			},
		},
		Earlier: []monitor.FailureRecord{
			{
				Monitor: monitor.FailureMonitorRewrite, Event: 1, Rule: "Guarded",
				Category: monitor.FailureRestriction, Message: "restriction violated: Eq(1, 0)", Branch: 7,
			},
		},
		Counts: monitor.FailureCounts{NoCandidate: 1, Restriction: 3, EpsilonDepth: 1},
	}
}

func TestWriteFailureReport(t *testing.T) {
	var out bytes.Buffer
	writeFailureReport(&out, testFailureReport())
	want := "failed candidates and branches at the rejected event:\n" +
		"  core event 7 (raw event 3, alternative 2, position 1) branch 000000000000002a: " +
		"rule Check: restriction: restriction violated: Eq('1', '2')\n" +
		"  core event 7 branch 000000000000beef: no_candidate: no rule candidate consumes the event\n" +
		"earlier failures, as context (the most recent 1 of 3):\n" +
		"  rewrite event 1 branch 0000000000000007: rule Guarded: restriction: restriction violated: Eq(1, 0)\n" +
		"failure counts: no_candidate 1, restriction 3, epsilon_depth 1\n"
	if out.String() != want {
		t.Fatalf("report =\n%s\nwant\n%s", out.String(), want)
	}

	out.Reset()
	writeFailureReport(&out, monitor.FailureReport{
		Final:  testFailureReport().Final[1:],
		Counts: monitor.FailureCounts{NoCandidate: 1},
	})
	if strings.Contains(out.String(), "earlier failures") {
		t.Fatalf("report without earlier failures =\n%s", out.String())
	}

	// A message with content from the trace stays on one line.
	out.Reset()
	writeFailureReport(&out, monitor.FailureReport{
		Final: []monitor.FailureRecord{{
			Monitor: monitor.FailureMonitorCore, Event: 1, Category: monitor.FailureRestriction,
			Rule: "Check", Message: "restriction violated: Eq('a\nError: injected\r\t\x00', 'b')", Branch: 1,
		}},
		Counts: monitor.FailureCounts{Restriction: 1},
	})
	if want := "  core event 1 branch 0000000000000001: rule Check: restriction: " +
		`restriction violated: Eq('a\nError: injected\r\t\x00', 'b')` + "\n"; strings.Split(out.String(), "\n")[1]+"\n" != want {
		t.Fatalf("escaped record line = %q, want %q", strings.Split(out.String(), "\n")[1], want)
	}
	if strings.Count(out.String(), "\n") != 3 {
		t.Fatalf("report = %q, want three lines", out.String())
	}
}

func TestViolationHookPayloadReportsFailures(t *testing.T) {
	violation := testViolationInfo()
	violation.Failures = testFailureReport()
	encoded, err := json.Marshal(newViolationHookPayload(violation, "model.spthy", "", 0, ""))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	want := `{"final":[{"monitor":"core","event":7,"rewrite":{"raw_event":3,"alternative":2,"position":1},` +
		`"rule":"Check","category":"restriction","message":"restriction violated: Eq('1', '2')","branch":"000000000000002a"},` +
		`{"monitor":"core","event":7,"category":"no_candidate","message":"no rule candidate consumes the event","branch":"000000000000beef"}],` +
		`"earlier":[{"monitor":"rewrite","event":1,"rule":"Guarded","category":"restriction","message":"restriction violated: Eq(1, 0)",` +
		`"branch":"0000000000000007"}],"counts":{"no_candidate":1,"restriction":3,"epsilon_depth":1}}`
	var payload map[string]any
	var wantValue any
	if err := errors.Join(json.Unmarshal(encoded, &payload), json.Unmarshal([]byte(want), &wantValue)); err != nil {
		t.Fatalf("decode payload or expected failures: %v", err)
	}
	if !reflect.DeepEqual(payload["failures"], wantValue) {
		t.Fatalf("payload = %s, want failures %s", encoded, want)
	}
}

// TestMonitorReportsRewriteRejectionReasons checks a rejection on the rewrite
// side, because no rewrite rule matches or because every rewrite candidate
// fails its evaluation: the rewrite violation error with the reasons on
// stderr, and neither the hook nor the PID termination. The rewrite command
// reports the same reasons.
func TestMonitorReportsRewriteRejectionReasons(t *testing.T) {
	for _, test := range []struct {
		name     string
		rewrite  string
		category string
	}{
		{
			name:     "no candidate",
			rewrite:  "rule Rewrite [no-decomp, trigger=[<reportOther(), <>>]]:\n  [ ] --[ PPEvent(<reportRewritten(), <>>) ]-> [ ]\n",
			category: "no_candidate",
		},
		{
			name: "every candidate fails its evaluation",
			rewrite: "rule Rewrite [no-decomp, trigger=[<monitorTestEvent(), <>>]]:\n" +
				"  [ ] --[ PPEvent(<reportRewritten(add('9223372036854775807', '1')), <>>) ]-> [ ]\n",
			category: "evaluation",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			markerPath := filepath.Join(t.TempDir(), "marker")
			t.Setenv(testMarkerPathEnv, markerPath)
			hook := writeViolationHook(t, fmt.Sprintf("printf 'ran' > \"$%s\"\n", testMarkerPathEnv))
			dir := t.TempDir()
			mainPath := filepath.Join(dir, "main.spthy")
			rewritePath := filepath.Join(dir, "rewrite.spthy")
			for path, spec := range map[string]string{
				mainPath:    "theory Main\nbegin\nrule Main [no-decomp, trigger=[<reportRewritten(), <>>]]:\n  [ ] --> [ ]\nend\n",
				rewritePath: "theory Rewrite\nbegin\n" + test.rewrite + "end\n",
			} {
				if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
					t.Fatalf("write specification: %v", err)
				}
			}
			kills := 0
			cmd := monitorTestCommand()
			config := MonitorConfig{
				In:                 writeMonitorInput(t, monitorEventLine(t, monitorTestEventName)),
				RewriteWith:        rewritePath,
				Pid:                123,
				OnViolation:        hook,
				OnViolationTimeout: testHookTimeout,
				terminateProcess: func(int) error {
					kills++
					return nil
				},
			}
			err := config.RunE(cmd, []string{mainPath})
			if err == nil || !strings.HasPrefix(err.Error(), "monitor events: process event ") ||
				!strings.HasSuffix(err.Error(), ": rewrite violation: no applicable rule found") {
				t.Fatalf("RunE error = %v, want the rewrite violation error", err)
			}
			if _, statErr := os.Stat(markerPath); !errors.Is(statErr, os.ErrNotExist) || kills != 0 {
				t.Fatalf("rewrite rejection ran the hook (%v) or terminated the process %d times", statErr, kills)
			}
			stderr := cmd.ErrOrStderr().(*bytes.Buffer).String()
			if !strings.HasPrefix(stderr, "failed candidates and branches at the rejected event:\n  rewrite event 1 branch ") ||
				!strings.Contains(stderr, ": "+test.category+": ") {
				t.Fatalf("stderr = %q, want the failure report of the rewriter with a %s record", stderr, test.category)
			}

			// The rewrite command reports the same rejection.
			cmd = monitorTestCommand()
			rewrite := RewriteConfig{In: config.In, Out: filepath.Join(dir, "out.jsonl")}
			if err := rewrite.RunE(cmd, []string{rewritePath}); err == nil || err.Error() != "rewrite events: rewrite violation at event 1: no applicable rule found <monitorTestEvent(), <>>" {
				t.Fatalf("rewrite RunE error = %v, want the rewrite violation", err)
			}
			if got := cmd.ErrOrStderr().(*bytes.Buffer).String(); got != stderr {
				t.Fatalf("rewrite stderr = %q, want %q", got, stderr)
			}
		})
	}
}

// TestMonitorReactsWhenEveryBranchFails checks that an event after which
// every branch failed its evaluation or was pruned for depth is a
// violation that runs the hook and the PID termination, and that a failed
// candidate beside a surviving branch runs neither.
func TestMonitorReactsWhenEveryBranchFails(t *testing.T) {
	event := `{"time":1,"event":{"name":"pair","type":"function","args":[{"name":"go","type":"function",` +
		`"args":[{"type":"constant","const_kind":"int","value":"9223372036854775807"}]},` +
		`{"name":"pair","type":"function","args":[]}]}}` + "\n"
	overflow := "rule Bad [no-decomp, trigger=[<go(v), r>]]:\n  [ ] --> [ Sum(add(v, v)) ]\n"
	sibling := "rule Good [no-decomp, trigger=[<go(v), r>]]:\n  [ ] --> [ ]\n"
	depth := "rule Start [no-decomp, trigger=[<go(v), r>]]:\n  [ ] --> [ A(), A() ]\n" +
		"rule Consume [no-decomp]:\n  [ A() ] --> [ ]\n"
	for _, test := range []struct {
		name     string
		rules    string
		category monitor.FailureCategory
	}{
		{name: "no rule matches", rules: "rule Other [no-decomp, trigger=[<other(v), r>]]:\n  [ ] --> [ ]\n", category: monitor.FailureNoCandidate},
		{name: "every evaluation fails", rules: overflow, category: monitor.FailureEvaluation},
		{name: "every successor is pruned", rules: depth, category: monitor.FailureEpsilonDepth},
		{name: "a failed candidate beside a survivor", rules: overflow + sibling},
	} {
		t.Run(test.name, func(t *testing.T) {
			payloadPath := filepath.Join(t.TempDir(), "payload.json")
			t.Setenv(testPayloadPathEnv, payloadPath)
			hook := writeViolationHook(t, fmt.Sprintf("cat > \"$%s\"\n", testPayloadPathEnv))
			specPath := filepath.Join(t.TempDir(), "model.spthy")
			if err := os.WriteFile(specPath, []byte("theory M\nbegin\n"+test.rules+"end\n"), 0o600); err != nil {
				t.Fatalf("write specification: %v", err)
			}
			kills := 0
			config := MonitorConfig{
				In:                 writeMonitorInput(t, []byte(event)),
				Pid:                123,
				OnViolation:        hook,
				OnViolationTimeout: testHookTimeout,
				terminateProcess: func(int) error {
					kills++
					return nil
				},
			}
			cmd := monitorTestCommand()
			err := config.RunE(cmd, []string{specPath})
			payloadBytes, readErr := os.ReadFile(payloadPath)
			if test.category == "" {
				if err != nil || !errors.Is(readErr, os.ErrNotExist) || kills != 0 {
					t.Fatalf("RunE = %v, hook payload error %v, kills %d; want acceptance without reaction", err, readErr, kills)
				}
				return
			}
			if !errors.Is(err, monitor.ErrNoApplicableRule) || readErr != nil || kills != 1 {
				t.Fatalf("RunE = %v, hook payload error %v, kills %d; want a violation with hook and termination", err, readErr, kills)
			}
			var payload violationHookPayload
			if err := json.Unmarshal(payloadBytes, &payload); err != nil {
				t.Fatalf("unmarshal hook payload: %v", err)
			}
			if len(payload.Failures.Final) == 0 || payload.Failures.Final[0].Category != test.category {
				t.Fatalf("hook payload failures = %+v, want %s", payload.Failures, test.category)
			}
			if stderr := cmd.ErrOrStderr().(*bytes.Buffer).String(); !strings.HasPrefix(stderr,
				"failed candidates and branches at the rejected event:\n  core event 1 branch ") || !strings.Contains(stderr, ": "+string(test.category)+": ") {
				t.Fatalf("stderr = %q, want the failure report with a %s record", stderr, test.category)
			}
		})
	}
}

func TestFailureCountsOmitZerosAndKeepMixedCategories(t *testing.T) {
	report := monitor.FailureReport{Counts: monitor.FailureCounts{Restriction: 2, Evaluation: 1}}
	var output strings.Builder
	writeFailureReport(&output, report)
	if !strings.Contains(output.String(), "failure counts: restriction 2, evaluation 1\n") {
		t.Fatalf("summary = %s", output.String())
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Counts) != 2 || decoded.Counts["restriction"] != 2 || decoded.Counts["evaluation"] != 1 {
		t.Fatalf("counts = %s", encoded)
	}
}
