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
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/specmon/specmon/monitor"
	"github.com/spf13/cobra"
)

// MonitorConfig is the configuration for the monitor subcommand.
type MonitorConfig struct {
	In       string `flag:"in"   short:"i" desc:"input path"`
	Out      string `flag:"out"  short:"o" desc:"output path"`
	PreTrace string `flag:"pre-trace" short:"p" desc:"pre-trace path"`
	Pid      int    `flag:"pid"  short:"P" desc:"PID of the monitored process to terminate"`
}

// RunE runs the monitor subcommand.
func (r MonitorConfig) RunE(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Root().Flags().GetBool("quiet")
	pid, err := cmd.Root().Flags().GetInt("pid")
	if err != nil {
		pid = -1
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)

	var m *monitor.Monitor
	go func() {
		<-sigs

		fmt.Fprintln(os.Stderr, "SIGTERM received, exiting...")
		m.Stats().EndTime = time.Now()
		fmt.Fprintln(os.Stderr, m.Stats().JSON())

		os.Exit(0)
	}()

	specPath := args[0]

	role, _ := cmd.Root().Flags().GetString("role")
	decompose, _ := cmd.Root().Flags().GetBool("decompose")

	_, _, decompRules, err := ProcessRules(specPath, role, decompose)
	if err != nil {
		return err
	}

	eventSource, err := getEventSource(r.In)
	if err != nil {
		return fmt.Errorf("cannot open in file: %w", err)
	}
	defer eventSource.Close()

	source := io.Reader(eventSource)

	if r.PreTrace != "" {
		preTrace, err := os.Open(r.PreTrace)
		if err != nil {
			return fmt.Errorf("cannot open pre-trace file: %w", err)
		}
		defer preTrace.Close()

		source = io.MultiReader(preTrace, eventSource)
	}

	// events, errs := monitor.ReadEvents(source)

	// go func() {
	// 	for err := range errs {
	// 		log.Fatal(err)
	// 	}
	// }()

	m, err = monitor.NewMonitor(decompRules)
	if err != nil {
		return fmt.Errorf("cannot create monitor: %w", err)
	}

	// _, consumed := m.ProcessEvents(events, false)
	_, consumed := m.ProcessEventsFromReader(source, false, pid)

	count := 1
	for c := range consumed {
		if !quiet {
			fmt.Printf("  %4d: %.120s\n", count, c)
		}
		count++
	}

	fmt.Println(m.Stats().JSON())

	return nil
}

// NewMonitorCmd creates a new command for the monitor subcommand.
func NewMonitorCmd() *cobra.Command {
	var monitorConfig MonitorConfig

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
