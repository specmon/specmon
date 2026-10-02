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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
)

const (
	violationHookTestEventName = "violationHookTestEvent"
	testPayloadPathEnv         = "SPECMON_TEST_PAYLOAD_PATH"
	testEnvironmentPathEnv     = "SPECMON_TEST_ENVIRONMENT_PATH"
	testReactionPathEnv        = "SPECMON_TEST_REACTION_PATH"
	testMarkerPathEnv          = "SPECMON_TEST_MARKER_PATH"
	// testHookTimeout is the hook timeout of tests that are not about the
	// timeout; it is generous, so that a slow machine does not fail them.
	testHookTimeout = time.Minute
)

func writeViolationHook(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "violation hook")
	contents := "#!/bin/sh\nset -eu\n" + body
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil { //nolint:gosec // The test hook must be executable.
		t.Fatalf("write violation hook: %v", err)
	}
	return path
}

func testViolationInfo() *monitor.ViolationInfo {
	eventTime := int64(123456789)
	return &monitor.ViolationInfo{
		Err:       fmt.Errorf("event rejected: %w", monitor.ErrNoApplicableRule),
		ErrorKind: monitor.ViolationKindNoApplicableRule,
		TimedEvent: &monitor.TimedEvent{
			Time: eventTime,
			Event: term.NewFunction(violationHookTestEventName, []term.Term{
				term.NewConstant("value"),
			}),
		},
		EventIndex: 7,
		Stats: monitor.StatsSummary{
			Received:    7,
			Processed:   6,
			TotalTimeNS: 99,
		},
	}
}

func environmentValues(environment []string) map[string]string {
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	return values
}

func TestExecuteViolationHookPayloadEnvironmentAndOutput(t *testing.T) {
	payloadPath := filepath.Join(t.TempDir(), "payload.json")
	environmentPath := filepath.Join(t.TempDir(), "environment.txt")
	t.Setenv(testPayloadPathEnv, payloadPath)
	t.Setenv(testEnvironmentPathEnv, environmentPath)
	t.Setenv(violationHookKindEnv, "stale-kind")
	t.Setenv(violationHookErrorKindEnv, "stale-error")
	t.Setenv(violationHookEventIndexEnv, "999")
	t.Setenv(violationHookPIDEnv, "999")

	hook := writeViolationHook(t, fmt.Sprintf(`cat > "$%s"
printf '%%s|%%s|%%s|%%s\n' "$%s" "$%s" "$%s" "$%s" > "$%s"
printf 'hook stdout\n'
printf 'hook stderr\n' >&2
`,
		testPayloadPathEnv,
		violationHookKindEnv,
		violationHookErrorKindEnv,
		violationHookEventIndexEnv,
		violationHookPIDEnv,
		testEnvironmentPathEnv,
	))
	payload := newViolationHookPayload(testViolationInfo(), "model.spthy", "client", 1234, "rewrite.spthy")

	var output bytes.Buffer
	if err := executeViolationHook(hook, testHookTimeout, payload, &output); err != nil {
		t.Fatalf("executeViolationHook: %v", err)
	}
	if got := output.String(); !strings.Contains(got, "hook stdout\n") || !strings.Contains(got, "hook stderr\n") {
		t.Fatalf("forwarded hook output = %q", got)
	}

	payloadBytes, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("read hook payload: %v", err)
	}
	if !bytes.HasSuffix(payloadBytes, []byte("\n")) {
		t.Fatalf("hook payload is not newline terminated: %q", payloadBytes)
	}
	var gotPayload violationHookPayload
	if err := json.Unmarshal(payloadBytes, &gotPayload); err != nil {
		t.Fatalf("unmarshal hook payload: %v", err)
	}
	if gotPayload.SchemaVersion != violationHookSchemaVersion || gotPayload.Kind != violationHookKind {
		t.Fatalf("hook payload version or kind = %#v", gotPayload)
	}
	if gotPayload.ErrorKind != monitor.ViolationKindNoApplicableRule || gotPayload.EventIndex != 7 {
		t.Fatalf("hook payload classification = %#v", gotPayload)
	}
	if gotPayload.Time == nil || *gotPayload.Time != 123456789 || gotPayload.Event == nil {
		t.Fatalf("hook payload event = %#v", gotPayload)
	}
	if gotPayload.EventTerm == "" || gotPayload.SpecPath != "model.spthy" || gotPayload.Role != "client" {
		t.Fatalf("hook payload context = %#v", gotPayload)
	}
	if gotPayload.PID != 1234 || gotPayload.RewriteWith != "rewrite.spthy" || gotPayload.Stats.Received != 7 {
		t.Fatalf("hook payload optional fields = %#v", gotPayload)
	}

	environmentBytes, err := os.ReadFile(environmentPath)
	if err != nil {
		t.Fatalf("read hook environment: %v", err)
	}
	wantEnvironment := "violation|no_applicable_rule|7|1234\n"
	if string(environmentBytes) != wantEnvironment {
		t.Fatalf("hook environment = %q, want %q", environmentBytes, wantEnvironment)
	}
}

func TestViolationHookEnvironmentRemovesStalePID(t *testing.T) {
	payload := newViolationHookPayload(testViolationInfo(), "model.spthy", "", 0, "")
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal hook payload: %v", err)
	}
	for _, field := range []string{`"pid"`, `"role"`, `"rewrite_with"`} {
		if bytes.Contains(payloadJSON, []byte(field)) {
			t.Fatalf("optional field %s was not omitted: %s", field, payloadJSON)
		}
	}
	environment := violationHookEnvironment([]string{
		"KEEP=value",
		violationHookKindEnv + "=stale",
		violationHookErrorKindEnv + "=stale",
		violationHookEventIndexEnv + "=stale",
		violationHookPIDEnv + "=stale",
	}, payload)
	values := environmentValues(environment)
	if values["KEEP"] != "value" {
		t.Fatalf("unrelated environment changed: %#v", values)
	}
	if values[violationHookKindEnv] != violationHookKind ||
		values[violationHookErrorKindEnv] != monitor.ViolationKindNoApplicableRule ||
		values[violationHookEventIndexEnv] != "7" {
		t.Fatalf("hook environment was not replaced: %#v", values)
	}
	if _, ok := values[violationHookPIDEnv]; ok {
		t.Fatalf("stale PID environment survived: %#v", values)
	}
}

func TestExecuteViolationHookDoesNotWaitForInheritedStreams(t *testing.T) {
	hook := writeViolationHook(t, "sleep 10 &\n")
	start := time.Now()
	var output bytes.Buffer
	if err := executeViolationHook(hook, testHookTimeout, violationHookPayload{}, &output); err != nil {
		t.Fatalf("executeViolationHook: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("hook took %s, want it to end after the hook exits", elapsed)
	}
}

func TestMonitorRunsViolationHookBeforePIDTermination(t *testing.T) {
	reactionPath := filepath.Join(t.TempDir(), "reaction.txt")
	payloadPath := filepath.Join(t.TempDir(), "payload.json")
	t.Setenv(testReactionPathEnv, reactionPath)
	t.Setenv(testPayloadPathEnv, payloadPath)
	hook := writeViolationHook(t, fmt.Sprintf(`printf 'hook\n' >> "$%s"
cat > "$%s"
printf 'hook stdout\n'
printf 'hook stderr\n' >&2
`, testReactionPathEnv, testPayloadPathEnv))

	specPath := filepath.Join("..", "testdata", "translation", "no_decomposition", "input.spthy")
	config := MonitorConfig{
		In:                 writeMonitorInput(t, monitorTestEventLine(t)),
		Pid:                123,
		OnViolation:        hook,
		OnViolationTimeout: testHookTimeout,
		terminateProcess: func(pid int) error {
			if pid != 123 {
				t.Fatalf("terminate process called with pid %d", pid)
			}
			file, err := os.OpenFile(reactionPath, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = file.WriteString("pid\n")
			return err
		},
	}
	cmd := monitorTestCommand()
	err := config.RunE(cmd, []string{specPath})
	if !errors.Is(err, monitor.ErrNoApplicableRule) {
		t.Fatalf("RunE error = %v, want ErrNoApplicableRule", err)
	}
	reaction, err := os.ReadFile(reactionPath)
	if err != nil {
		t.Fatalf("read reaction order: %v", err)
	}
	if string(reaction) != "hook\npid\n" {
		t.Fatalf("reaction order = %q", reaction)
	}
	stderr := cmd.ErrOrStderr().(*bytes.Buffer).String()
	if !strings.Contains(stderr, "hook stdout\n") || !strings.Contains(stderr, "hook stderr\n") {
		t.Fatalf("command stderr did not receive hook output: %q", stderr)
	}

	payloadBytes, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("read monitor hook payload: %v", err)
	}
	var payload violationHookPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshal monitor hook payload: %v", err)
	}
	if payload.EventIndex != 1 || payload.Stats.Received != 1 || payload.Stats.Processed != 0 {
		t.Fatalf("monitor hook payload boundary = %#v", payload)
	}
}

func TestMonitorDoesNotRunViolationHookForOrdinaryErrors(t *testing.T) {
	markerPath := filepath.Join(t.TempDir(), "marker")
	t.Setenv(testMarkerPathEnv, markerPath)
	hook := writeViolationHook(t, fmt.Sprintf("printf 'ran' > \"$%s\"\n", testMarkerPathEnv))
	var kills atomic.Int32
	config := MonitorConfig{
		In:                 writeMonitorInput(t, []byte("not json\n")),
		Pid:                123,
		OnViolation:        hook,
		OnViolationTimeout: testHookTimeout,
		terminateProcess: func(int) error {
			kills.Add(1)
			return nil
		},
	}
	specPath := filepath.Join("..", "testdata", "translation", "no_decomposition", "input.spthy")
	if err := config.RunE(monitorTestCommand(), []string{specPath}); err == nil {
		t.Fatal("RunE returned nil for malformed input")
	}
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ordinary error ran violation hook: %v", err)
	}
	if kills.Load() != 0 {
		t.Fatalf("ordinary error terminated PID %d times", kills.Load())
	}
}

func TestViolationHookFailureDoesNotSkipPIDTermination(t *testing.T) {
	exitHook := writeViolationHook(t, "exit 7\n")
	timeoutHook := writeViolationHook(t, "exec /bin/sleep 5\n")
	for _, test := range []struct {
		name        string
		path        string
		timeout     time.Duration
		wantWarning string
	}{
		{
			name:        "start",
			path:        filepath.Join(t.TempDir(), "missing"),
			timeout:     testHookTimeout,
			wantWarning: "violation hook failed to start",
		},
		{
			name:        "exit",
			path:        exitHook,
			timeout:     testHookTimeout,
			wantWarning: "violation hook exited with an error",
		},
		{
			name:        "timeout",
			path:        timeoutHook,
			timeout:     20 * time.Millisecond,
			wantWarning: "violation hook timed out after 20ms",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var kills atomic.Int32
			config := MonitorConfig{
				Pid:                123,
				OnViolation:        test.path,
				OnViolationTimeout: test.timeout,
			}
			cmd := monitorTestCommand()
			config.handleViolation(cmd, testViolationInfo(), "model.spthy", "", func(pid int) error {
				if pid != 123 {
					t.Fatalf("terminate process called with pid %d", pid)
				}
				kills.Add(1)
				return nil
			})
			if kills.Load() != 1 {
				t.Fatalf("hook failure terminated PID %d times", kills.Load())
			}
			if got := cmd.ErrOrStderr().(*bytes.Buffer).String(); !strings.Contains(got, test.wantWarning) {
				t.Fatalf("hook warning = %q, want %q", got, test.wantWarning)
			}
		})
	}
}

func TestMonitorReactionFailuresDoNotMaskViolation(t *testing.T) {
	specPath := filepath.Join("..", "testdata", "translation", "no_decomposition", "input.spthy")
	config := MonitorConfig{
		In:                 writeMonitorInput(t, monitorTestEventLine(t)),
		Pid:                123,
		OnViolation:        filepath.Join(t.TempDir(), "missing"),
		OnViolationTimeout: testHookTimeout,
		terminateProcess: func(int) error {
			return errors.New("test PID failure")
		},
	}
	cmd := monitorTestCommand()
	err := config.RunE(cmd, []string{specPath})
	if !errors.Is(err, monitor.ErrNoApplicableRule) {
		t.Fatalf("RunE error = %v, want ErrNoApplicableRule", err)
	}
	stderr := cmd.ErrOrStderr().(*bytes.Buffer).String()
	if !strings.Contains(stderr, "violation hook failed to start") ||
		!strings.Contains(stderr, "failed to kill process: test PID failure") {
		t.Fatalf("reaction warnings = %q", stderr)
	}
}
