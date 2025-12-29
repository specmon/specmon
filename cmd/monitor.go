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
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
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
	defines, _ := cmd.Root().Flags().GetStringSlice("defines")
	verbose, _ := cmd.Root().Flags().GetBool("verbose")

	_, _, decompRules, err := ProcessRules(specPath, role, decompose)
	if err != nil {
		return err
	}

	eventSource, err := getEventSource(r.In)
	if err != nil {
		return fmt.Errorf("cannot open in file: %w", err)
	}
	defer eventSource.Close()

	// Create the main monitor
	m, err = monitor.NewMonitor(decompRules)
	if err != nil {
		return fmt.Errorf("cannot create monitor: %w", err)
	}

	if r.RewriteWith != "" {
		// Integrated rewrite mode: first process pre-trace directly to main monitor,
		// then feed live input through the rewriter and into the main monitor.
		rewriteRules, _, _, err := ProcessRules(r.RewriteWith, role, decompose, defines)
		if err != nil {
			return fmt.Errorf("cannot process rewrite rules: %w", err)
		}

		count := 1
		start := time.Now()
		if !quiet && !verbose {
			printHeader(startHeader(specPath, len(m.Configs())))
		}

		// 1) Pre-trace to main monitor (no rewrite)
		if r.PreTrace != "" {
			preTrace, err := os.Open(r.PreTrace)
			if err != nil {
				return fmt.Errorf("cannot open pre-trace file: %w", err)
			}
			defer preTrace.Close()

			events := monitor.ParseEvents(preTrace, pid)
			_, consumedPre := m.ProcessEvents(events, false, pid)
			for c := range consumedPre {
				printEventLine(quiet, verbose, specPath, start, count, len(m.Configs()), c)
				count++
			}
		}

		// 2) Live events: rewriter -> main monitor via channel
		rewriter, err := monitor.NewMonitor(rewriteRules)
		if err != nil {
			return fmt.Errorf("cannot create rewrite monitor: %w", err)
		}

		rewriterEvents := monitor.ParseEvents(eventSource, pid)
		outs, _ := rewriter.ProcessEvents(rewriterEvents, true, pid)
		_, consumedEvents := m.ProcessEvents(outs, false, pid)

		for c := range consumedEvents {
			printEventLine(quiet, verbose, specPath, start, count, len(m.Configs()), c)
			count++
		}

		if !quiet && !verbose {
			printHeader(compactHeader(specPath, count-1, len(m.Configs()), start))
		}
		if verbose {
			fmt.Println(m.Stats().JSON())
		}
		return nil
	}

	// No rewrite: use original logic with MultiReader for pre-trace
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
	start := time.Now()
	if !quiet && !verbose {
		printHeader(startHeader(specPath, len(m.Configs())))
	}
	for c := range consumed {
		printEventLine(quiet, verbose, specPath, start, count, len(m.Configs()), c)
		count++
	}

	if !quiet && !verbose {
		printHeader(compactHeader(specPath, count-1, len(m.Configs()), start))
	}
	if verbose {
		fmt.Println(m.Stats().JSON())
	}

	return nil
}

func printEventLine(quiet, verbose bool, specPath string, start time.Time, count, configs int, event term.Term) {
	if quiet {
		return
	}

	if verbose {
		fmt.Printf("  %4d: %.120s\n", count, formatVerboseEvent(event))
		return
	}

	fmt.Printf("OK %4d  %s\n", count, formatCompactEvent(event))
}

func compactHeader(specPath string, count, configs int, start time.Time) string {
	elapsed := time.Since(start)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(count) / elapsed.Seconds()
	}
	content := fmt.Sprintf(
		"Monitoring: %s | Events: %d | Configs: %d | Rate: %.1f/s | Time: %s",
		specPath,
		count,
		configs,
		rate,
		elapsed.Round(100*time.Millisecond),
	)
	return formatHeaderBox(content)
}

func formatCompactEvent(t term.Term) string {
	fn, err := term.AsFunction(t)
	if err != nil || fn == nil {
		return formatCompactTerm(t)
	}

	if fn.Name == term.PairFunctionName && len(fn.Args) == 2 {
		if call, err := term.AsFunction(fn.Args[0]); err == nil && call != nil {
			args := append([]term.Term{}, call.Args...)
			args = append(args, fn.Args[1])
			return formatCompactCall(call.Name, args)
		}
	}

	return formatCompactCall(fn.Name, fn.Args)
}

func formatVerboseEvent(t term.Term) string {
	fn, err := term.AsFunction(t)
	if err != nil || fn == nil {
		return formatVerboseTerm(t)
	}

	return formatVerboseTerm(fn)
}

func formatCompactCall(name string, args []term.Term) string {
	if name == term.PairFunctionName {
		return formatCompactPair(args)
	}
	if args == nil {
		return fmt.Sprintf("%s()", colorEventName(name))
	}

	var b strings.Builder
	b.WriteString(colorEventName(name))
	b.WriteString("(")
	for i, arg := range args {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(formatCompactTerm(arg))
	}
	b.WriteString(")")
	return b.String()
}

func formatCompactTerm(t term.Term) string {
	switch v := t.(type) {
	case *term.Constant[int]:
		return fmt.Sprintf("%d", v.Value)
	case *term.Constant[string]:
		return fmt.Sprintf("'%s'", v.Value)
	case *term.Constant[[]byte]:
		return fmt.Sprintf("<bytes:%d>", len(v.Value))
	case *term.Variable:
		return v.Name
	case *term.Function:
		return formatCompactCall(v.Name, v.Args)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func formatVerboseTerm(t term.Term) string {
	switch v := t.(type) {
	case *term.Constant[int], *term.Constant[string], *term.Constant[[]byte]:
		return v.String()
	case *term.Variable:
		return v.Name
	case *term.Function:
		return formatVerboseCall(v.Name, v.Args)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func formatVerboseCall(name string, args []term.Term) string {
	if name == term.PairFunctionName {
		return formatVerbosePair(args)
	}
	if args == nil {
		return fmt.Sprintf("%s()", name)
	}

	var b strings.Builder
	b.WriteString(name)
	b.WriteString("(")
	for i, arg := range args {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(formatVerboseTerm(arg))
	}
	b.WriteString(")")
	return b.String()
}

func formatCompactPair(args []term.Term) string {
	if args == nil {
		return "<>"
	}

	var b strings.Builder
	b.WriteString("<")
	for i, arg := range args {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(formatCompactTerm(arg))
	}
	b.WriteString(">")
	return b.String()
}

func formatVerbosePair(args []term.Term) string {
	if args == nil {
		return "<>"
	}

	var b strings.Builder
	b.WriteString("<")
	for i, arg := range args {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(formatVerboseTerm(arg))
	}
	b.WriteString(">")
	return b.String()
}

func formatHeaderBox(content string) string {
	width := len([]rune(content)) + 2
	top := "┌" + strings.Repeat("─", width) + "┐"
	mid := fmt.Sprintf("│ %s │", content)
	bot := "└" + strings.Repeat("─", width) + "┘"
	return strings.Join([]string{top, mid, bot}, "\n")
}

func printHeader(header string) {
	for _, line := range strings.Split(header, "\n") {
		fmt.Println(line)
	}
}

func startHeader(specPath string, configs int) string {
	content := fmt.Sprintf("Monitoring started: %s | Configs: %d", specPath, configs)
	return formatHeaderBox(content)
}

func colorEventName(name string) string {
	if color.NoColor {
		return name
	}

	switch strings.ToLower(name) {
	case "send", "out", "sendmessage":
		return color.New(color.FgGreen).Sprint(name)
	case "recv", "receive", "in", "receivemessage":
		return color.New(color.FgCyan).Sprint(name)
	case "random", "fr":
		return color.New(color.FgMagenta).Sprint(name)
	case "hash", "hmac", "mac", "aead", "enc", "dec", "encrypt", "decrypt", "sign", "verify":
		return color.New(color.FgYellow).Sprint(name)
	case "setup":
		return color.New(color.FgBlue).Sprint(name)
	default:
		return name
	}
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
