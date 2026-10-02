// Copyright (C) 2025-2026 CISPA Helmholtz Center for Information Security
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
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
	"github.com/specmon/specmon/utils"
	"github.com/spf13/cobra"
)

// MonitorConfig is the configuration for the monitor subcommand.
type MonitorConfig struct {
	In                 string        `flag:"in"                   short:"i" desc:"input path (file, '-', host:port)"`
	Out                string        `flag:"out"                  short:"o" desc:"output path"`
	PreTrace           string        `flag:"pre-trace"            short:"p" desc:"pre-trace path"`
	Pid                int           `flag:"pid"                  short:"P" desc:"PID of the monitored process to terminate"`
	RewriteWith        string        `flag:"rewrite-with"         short:"R" desc:"rewrite theory (.spthy) to apply inline before monitoring"`
	OnViolation        string        `flag:"on-violation"                  desc:"executable to run after a monitor violation"`
	OnViolationTimeout time.Duration `flag:"on-violation-timeout"          desc:"maximum violation hook runtime, zero disables the timeout"`

	terminateProcess func(int) error
}

// RunE runs the monitor subcommand.
func (r *MonitorConfig) RunE(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Root().Flags().GetBool("quiet")
	if r.Pid < 0 || (r.Pid == 0 && cmd.Flags().Changed("pid")) {
		return fmt.Errorf("pid must be a positive integer, got %d", r.Pid)
	}
	if r.OnViolationTimeout < 0 {
		return fmt.Errorf("on-violation-timeout cannot be negative, got %s", r.OnViolationTimeout)
	}
	terminateProcess := r.terminateProcess
	if terminateProcess == nil {
		terminateProcess = utils.KillProcess
	}

	runCtx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// After the first signal, a second one ends the process at once.
	context.AfterFunc(runCtx, stop)

	specPath := args[0]

	role, _ := cmd.Root().Flags().GetString("role")
	decompose, _ := cmd.Root().Flags().GetBool("decompose")
	defines, _ := cmd.Root().Flags().GetStringSlice("defines")

	// Parse main monitoring rules
	rules, err := ProcessRules(runCtx, specPath, role, decompose, defines)
	if err != nil {
		return err
	}

	// The input is opened before the pre-trace is processed, so that a
	// client can connect to a listening socket in the meantime. The
	// monitor closes it; closing it again on an early return is harmless.
	eventSource, err := openInputReader(r.In)
	if err != nil {
		return fmt.Errorf("cannot open input: %w", err)
	}
	defer eventSource.Close()

	// Create the main monitor
	m, err := monitor.NewMonitor(rules.Executable)
	if err != nil {
		return fmt.Errorf("cannot create monitor: %w", err)
	}

	count := 1
	onConsumed := func(event term.Term) error {
		if !quiet {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "  %4d: %.120s\n", count, event); err != nil {
				return fmt.Errorf("write consumed event: %w", err)
			}
		}
		count++
		return nil
	}

	var rewriter *monitor.Monitor
	if r.RewriteWith != "" {
		// Rewrite rules translate instrumentation events independently of the
		// monitored protocol role.
		rewriteRules, err := ProcessRules(runCtx, r.RewriteWith, role, decompose, defines)
		if err != nil {
			return fmt.Errorf("cannot process rewrite rules: %w", err)
		}
		rewriter, err = monitor.NewMonitor(rewriteRules.Parsed)
		if err != nil {
			return fmt.Errorf("cannot create rewrite monitor: %w", err)
		}
	}

	if r.PreTrace != "" {
		preTrace, err := os.Open(r.PreTrace)
		if err != nil {
			return fmt.Errorf("cannot open pre-trace file: %w", err)
		}
		violation, runErr := m.Run(runCtx, preTrace, onConsumed)
		if violation != nil {
			fmt.Fprintln(cmd.OutOrStdout(), m.Stats().JSON())
			r.handleViolation(cmd, violation, specPath, role, terminateProcess)
			return violationError("monitor pre-trace violation", violation)
		}
		if runErr != nil {
			if errors.Is(runErr, context.Canceled) && cmd.Context().Err() == nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "signal received, exiting")
				fmt.Fprintln(cmd.OutOrStdout(), m.Stats().JSON())
				return nil
			}
			return fmt.Errorf("process pre-trace: %w", runErr)
		}
	}

	var violation *monitor.ViolationInfo
	var runErr error
	if rewriter == nil {
		violation, runErr = m.Run(runCtx, eventSource, onConsumed)
	} else {
		violation, runErr = monitor.RunPipeline(runCtx, rewriter, m, eventSource, onConsumed)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), m.Stats().JSON()); err != nil && violation == nil && runErr == nil {
		return fmt.Errorf("write monitor statistics: %w", err)
	}
	if violation != nil {
		r.handleViolation(cmd, violation, specPath, role, terminateProcess)
		return violationError("monitor violation", violation)
	}
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) && cmd.Context().Err() == nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "signal received, exiting")
			return nil
		}
		return fmt.Errorf("monitor events: %w", runErr)
	}

	return nil
}

func (r *MonitorConfig) handleViolation(
	cmd *cobra.Command,
	violation *monitor.ViolationInfo,
	specPath string,
	role string,
	terminateProcess func(int) error,
) {
	if r.OnViolation != "" {
		payload := newViolationHookPayload(violation, specPath, role, r.Pid, r.RewriteWith)
		if err := executeViolationHook(r.OnViolation, r.OnViolationTimeout, payload, cmd.ErrOrStderr()); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
		}
	}

	if r.Pid > 0 {
		if err := terminateProcess(r.Pid); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "failed to kill process: %v\n", err)
		}
	}
}

// violationError is the error with which a violation ends the command. It
// names the rejected event and its index.
func violationError(kind string, violation *monitor.ViolationInfo) error {
	return fmt.Errorf("%s at event %d: %w %s", kind, violation.EventIndex, violation.Err, violation.TimedEvent.Event)
}

// NewMonitorCmd creates a new command for the monitor subcommand.
func NewMonitorCmd() *cobra.Command {
	monitorConfig := MonitorConfig{
		OnViolationTimeout: defaultViolationHookTimeout,
	}

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "monitor the event trace",
		// Long:  `A specification monitor based on multiset-rewrite rules`,
		RunE: monitorConfig.RunE,
		Args: cobra.ExactArgs(1),
	}

	addFlagsFromStruct(cmd, &monitorConfig)

	return cmd
}
