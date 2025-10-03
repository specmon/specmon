// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
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
// along with program. If not, see <https://www.gnu.org/licenses/>.

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/specmon/specmon/monitor"
	"github.com/spf13/cobra"
)

// RewriteConfig is a configuration of the rewrite subcommand.
type RewriteConfig struct {
	JSON bool   `flag:"json" short:"j" desc:"output in json format"`
	In   string `flag:"in"   short:"i" desc:"input path (file, '-', host:port)"`
	Out  string `flag:"out"  short:"o" desc:"output path"`
	Pid  int    `flag:"pid"  short:"P" desc:"PID of the monitored process to terminate"`
}

// RunE runs the rewrite subcommand.
func (r *RewriteConfig) RunE(cmd *cobra.Command, args []string) error {
	// quiet, _ := cmd.Root().Flags().GetBool("quiet")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)

	var m *monitor.Monitor
	go func() {
		<-sigs

		fmt.Fprintln(os.Stderr, "SIGTERM received, exiting...")

		os.Exit(0)
	}()

	specPath := args[0]

	role, _ := cmd.Root().Flags().GetString("role")
	decompose, _ := cmd.Root().Flags().GetBool("decompose")
	defines, _ := cmd.Root().Flags().GetStringSlice("defines")

	_, _, decompRules, err := ProcessRules(specPath, role, decompose, defines)
	if err != nil {
		return fmt.Errorf("cannot process rules: %w", err)
	}

	eventSource, err := openInputReader(r.In)
	if err != nil {
		return fmt.Errorf("cannot open input: %w", err)
	}
	defer eventSource.Close()

	// Retrieve User Settings
	// factArgMaxLen specifies the maximum length of a fact's arguments before they are truncated in log output.
	logArgTruncate, err := cmd.Root().Flags().GetInt64("log-arg-truncate")

	// Define User Settings for Monitor
	settings := make(map[string]interface{})
	settings["logArgTruncate"] = logArgTruncate

	m, err = monitor.NewMonitor(decompRules, settings)
	if err != nil {
		return fmt.Errorf("cannot create monitor: %w", err)
	}

	events := monitor.ParseEvents(eventSource, -1)
	outs, _ := m.ProcessEvents(events, true, -1)

	outFile, err := getOutputFile(r.Out)
	if err != nil {
		return fmt.Errorf("cannot open out file: %w", err)
	}
	defer outFile.Close()

	for out := range outs {
		if r.JSON {
			var b []byte

			b, err = json.Marshal(out)
			if err != nil {
				return fmt.Errorf("cannot marshal to json: %w", err)
			}
			_, err = fmt.Fprintln(outFile, string(b))
		} else {
			_, err = fmt.Fprintln(outFile, out)
		}

		if err != nil {
			return fmt.Errorf("cannot write to out file: %w", err)
		}
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
