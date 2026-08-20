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

type violationHookErrorKind int

const (
	violationHookStartError violationHookErrorKind = iota
	violationHookExitError
	violationHookTimeoutError
)

type violationHookError struct {
	kind violationHookErrorKind
	err  error
}

func (e *violationHookError) Error() string {
	return e.err.Error()
}

func (e *violationHookError) Unwrap() error {
	return e.err
}

func newViolationHookPayload(
	violation *monitor.ViolationInfo,
	specPath string,
	role string,
	pid int,
	rewriteWith string,
) violationHookPayload {
	payload := violationHookPayload{
		SchemaVersion: violationHookSchemaVersion,
		Kind:          violationHookKind,
		ErrorKind:     violation.ErrorKind,
		Error:         violation.Err.Error(),
		EventIndex:    violation.EventIndex,
		SpecPath:      specPath,
		Role:          role,
		RewriteWith:   rewriteWith,
		Stats:         violation.Stats,
	}
	if pid > 0 {
		payload.PID = pid
	}
	if violation.TimedEvent != nil {
		payload.Time = &violation.TimedEvent.Time
		payload.Event = violation.TimedEvent.Event
		if payload.Event != nil {
			payload.EventTerm = payload.Event.String()
		}
	}
	return payload
}

func executeViolationHook(
	ctx context.Context,
	path string,
	timeout time.Duration,
	payload violationHookPayload,
	output io.Writer,
) error {
	var input bytes.Buffer
	if err := json.NewEncoder(&input).Encode(payload); err != nil {
		return &violationHookError{kind: violationHookStartError, err: fmt.Errorf("encode payload: %w", err)}
	}

	hookCtx := context.WithoutCancel(ctx)
	cancel := func() {}
	if timeout > 0 {
		hookCtx, cancel = context.WithTimeout(hookCtx, timeout)
	}
	defer cancel()

	command := exec.CommandContext(hookCtx, path)
	command.Stdin = &input
	command.Stdout = output
	command.Stderr = output
	command.Env = violationHookEnvironment(os.Environ(), payload)
	if err := command.Start(); err != nil {
		return &violationHookError{kind: violationHookStartError, err: err}
	}
	if err := command.Wait(); err != nil {
		if errors.Is(hookCtx.Err(), context.DeadlineExceeded) {
			return &violationHookError{kind: violationHookTimeoutError, err: err}
		}
		return &violationHookError{kind: violationHookExitError, err: err}
	}
	return nil
}

func violationHookEnvironment(base []string, payload violationHookPayload) []string {
	environment := make([]string, 0, len(base)+4)
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case violationHookKindEnv,
			violationHookErrorKindEnv,
			violationHookEventIndexEnv,
			violationHookPIDEnv:
			continue
		default:
			environment = append(environment, entry)
		}
	}

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

func reportViolationHookError(output io.Writer, timeout time.Duration, err error) {
	var hookErr *violationHookError
	if !errors.As(err, &hookErr) {
		fmt.Fprintf(output, "violation hook failed: %v\n", err)
		return
	}

	switch hookErr.kind {
	case violationHookStartError:
		fmt.Fprintf(output, "violation hook failed to start: %v\n", hookErr)
	case violationHookExitError:
		fmt.Fprintf(output, "violation hook exited with an error: %v\n", hookErr)
	case violationHookTimeoutError:
		fmt.Fprintf(output, "violation hook timed out after %s: %v\n", timeout, hookErr)
	}
}
