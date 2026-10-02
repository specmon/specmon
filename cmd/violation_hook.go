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
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
)

const (
	violationHookSchemaVersion = "1"
	violationHookKind          = "violation"

	violationHookKindEnv       = "SPECMON_HOOK_KIND"
	violationHookErrorKindEnv  = "SPECMON_ERROR_KIND"
	violationHookEventIndexEnv = "SPECMON_EVENT_INDEX"
	violationHookPIDEnv        = "SPECMON_PID"

	defaultViolationHookTimeout = 5 * time.Second
	// violationHookWaitDelay bounds the wait for the hook's standard
	// streams after the hook has exited or timed out: a process that the
	// hook starts in the background may inherit them and keep them open.
	violationHookWaitDelay = time.Second
)

type violationHookPayload struct {
	SchemaVersion string               `json:"schema_version"`
	Kind          string               `json:"kind"`
	ErrorKind     string               `json:"error_kind"`
	Error         string               `json:"error"`
	EventIndex    int                  `json:"event_index"`
	Time          *int64               `json:"time,omitempty"`
	Event         *term.Function       `json:"event,omitempty"`
	EventTerm     string               `json:"event_term,omitempty"`
	SpecPath      string               `json:"spec_path"`
	Role          string               `json:"role,omitempty"`
	PID           int                  `json:"pid,omitempty"`
	RewriteWith   string               `json:"rewrite_with,omitempty"`
	Stats         monitor.StatsSummary `json:"stats"`
}

func newViolationHookPayload(
	violation *monitor.ViolationInfo,
	specPath string,
	role string,
	pid int,
	rewriteWith string,
) violationHookPayload {
	return violationHookPayload{
		SchemaVersion: violationHookSchemaVersion,
		Kind:          violationHookKind,
		ErrorKind:     violation.ErrorKind,
		Error:         violation.Err.Error(),
		EventIndex:    violation.EventIndex,
		Time:          &violation.TimedEvent.Time,
		Event:         violation.TimedEvent.Event,
		EventTerm:     violation.TimedEvent.Event.String(),
		SpecPath:      specPath,
		Role:          role,
		PID:           pid,
		RewriteWith:   rewriteWith,
		Stats:         violation.Stats,
	}
}

func executeViolationHook(
	path string,
	timeout time.Duration,
	payload violationHookPayload,
	output io.Writer,
) error {
	var input bytes.Buffer
	if err := json.NewEncoder(&input).Encode(payload); err != nil {
		return fmt.Errorf("violation hook failed to start: encode payload: %w", err)
	}

	// The hook runs to its end or its timeout, also after a signal.
	hookCtx, cancel := context.Background(), context.CancelFunc(func() {})
	if timeout > 0 {
		hookCtx, cancel = context.WithTimeout(hookCtx, timeout)
	}
	defer cancel()

	command := exec.CommandContext(hookCtx, path)
	command.Stdin = &input
	command.Stdout = output
	command.Stderr = output
	command.Env = violationHookEnvironment(os.Environ(), payload)
	command.WaitDelay = violationHookWaitDelay
	if err := command.Start(); err != nil {
		return fmt.Errorf("violation hook failed to start: %w", err)
	}
	if err := command.Wait(); err != nil {
		// The hook succeeded; only a process it left behind kept its
		// streams open.
		if errors.Is(err, exec.ErrWaitDelay) && command.ProcessState != nil && command.ProcessState.Success() {
			return nil
		}
		if errors.Is(hookCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("violation hook timed out after %s: %w", timeout, err)
		}
		return fmt.Errorf("violation hook exited with an error: %w", err)
	}
	return nil
}

func violationHookEnvironment(base []string, payload violationHookPayload) []string {
	// exec uses the last value of a repeated key, so only an inherited PID
	// that the payload does not replace must be removed.
	environment := slices.DeleteFunc(slices.Clone(base), func(entry string) bool {
		return strings.HasPrefix(entry, violationHookPIDEnv+"=")
	})
	environment = append(environment,
		violationHookKindEnv+"="+violationHookKind,
		violationHookErrorKindEnv+"="+payload.ErrorKind,
		violationHookEventIndexEnv+"="+strconv.Itoa(payload.EventIndex),
	)
	if payload.PID > 0 {
		environment = append(environment, violationHookPIDEnv+"="+strconv.Itoa(payload.PID))
	}
	return environment
}
