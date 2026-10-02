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
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/specmon/specmon/monitor"
	"github.com/spf13/cobra"
)

// RewriteConfig is a configuration of the rewrite subcommand.
type RewriteConfig struct {
	JSON bool   `flag:"json" short:"j" desc:"output in json format"`
	In   string `flag:"in"   short:"i" desc:"input path (file, '-', host:port)"`
	Out  string `flag:"out"  short:"o" desc:"output path"`
}

// RunE runs the rewrite subcommand.
func (r *RewriteConfig) RunE(cmd *cobra.Command, args []string) error {
	runCtx, stop := signalContext(cmd.Context())
	defer stop()

	specPath := args[0]

	role, _ := cmd.Root().Flags().GetString("role")
	decompose, _ := cmd.Root().Flags().GetBool("decompose")
	defines, _ := cmd.Root().Flags().GetStringSlice("defines")

	rules, err := ProcessRules(runCtx, specPath, role, decompose, defines)
	if err != nil {
		return fmt.Errorf("cannot process rules: %w", err)
	}

	eventSource, err := openInputReader(r.In)
	if err != nil {
		return fmt.Errorf("cannot open input: %w", err)
	}
	// The rewriter closes the input; closing it again on an early return
	// is harmless.
	defer eventSource.Close()
	m, err := monitor.NewMonitor(rules.Executable)
	if err != nil {
		return fmt.Errorf("cannot create monitor: %w", err)
	}

	outFile, err := getOutputFile(r.Out)
	if err != nil {
		return fmt.Errorf("cannot open out file: %w", err)
	}

	runErr := m.Rewrite(runCtx, eventSource, func(out *monitor.TimedEvent) error {
		if r.JSON {
			b, err := json.Marshal(out)
			if err != nil {
				return fmt.Errorf("cannot marshal to json: %w", err)
			}
			if _, err := fmt.Fprintln(outFile, string(b)); err != nil {
				return fmt.Errorf("cannot write to out file: %w", err)
			}
			return nil
		}
		if _, err := fmt.Fprintln(outFile, out); err != nil {
			return fmt.Errorf("cannot write to out file: %w", err)
		}
		return nil
	})

	var closeErr error
	if outFile != os.Stdout {
		closeErr = outFile.Close()
	}
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) && cmd.Context().Err() == nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "signal received, exiting")
			return nil
		}
		return fmt.Errorf("rewrite events: %w", runErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close out file: %w", closeErr)
	}

	return nil
}

// NewRewriteCmd creates a new command for the rewrite subcommand.
func NewRewriteCmd() *cobra.Command {
	var rewriteConfig RewriteConfig

	cmd := &cobra.Command{
		Use:   "rewrite",
		Short: "rewrite the input trace based on the rules",
		// Long:  `A specification monitor based on multiset-rewrite rules`,
		RunE: rewriteConfig.RunE,
		Args: cobra.ExactArgs(1),
	}

	addFlagsFromStruct(cmd, &rewriteConfig)

	return cmd
}
