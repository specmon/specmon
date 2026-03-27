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
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
	"github.com/spf13/cobra"
)

var (
	eventColorMu      sync.Mutex
	eventColorByName  = map[string]int{}
	eventColorPalette = []*color.Color{
		color.New(color.FgCyan),
		color.New(color.FgYellow),
		color.New(color.FgGreen),
		color.New(color.FgMagenta),
		color.New(color.FgBlue),
		color.New(color.FgHiCyan),
		color.New(color.FgHiYellow),
		color.New(color.FgHiGreen),
		color.New(color.FgHiMagenta),
		color.New(color.FgHiBlue),
	}
)

// MonitorConfig is the configuration for the monitor subcommand.
type MonitorConfig struct {
	In                 string `flag:"in"           short:"i" desc:"input path (file, '-', host:port)"`
	Out                string `flag:"out"          short:"o" desc:"output path"`
	PreTrace           string `flag:"pre-trace"    short:"p" desc:"pre-trace path"`
	Pid                int    `flag:"pid"          short:"P" desc:"PID of the monitored process to terminate"`
	RewriteWith        string `flag:"rewrite-with" short:"R" desc:"rewrite theory (.spthy) to apply inline before monitoring"`
	ShowAll            bool   `flag:"show-all-events"        desc:"show all expected events without truncation"`
	TraceConfig        int    `flag:"trace-config"           desc:"show only a specific configuration (1-based)"`
	ShowAllCfgs        bool   `flag:"show-all-configs"       desc:"show expected events for all configurations"`
	MaxSuggestions     int    `flag:"max-suggestions"        desc:"maximum expected events shown per event-name group (default: 10)"`
	Live               bool   `flag:"live"                   desc:"show live dashboard"`
	LiveHistory        int    `flag:"increase-history"       desc:"increase live history size (default: 2000)"`
	Progress           bool   `flag:"progress"               desc:"show progress bar for batch inputs"`
	InferFormats       bool   `flag:"infer-formats"           desc:"infer message formats from traces"`
	MinComponent       int    `flag:"min-component-length"    desc:"minimum bytes for inferred components (default: 2)"`
	MaxComponents      int    `flag:"max-components"          desc:"maximum components in inferred concatenations (default: 10)"`
	Confidence         string `flag:"inference-confidence"    desc:"show only HIGH|MEDIUM|LOW|ALL (default: MEDIUM)"`
	FormatReport       string `flag:"format-report"           desc:"write format inference report to file"`
	FormatReportStdout bool   `flag:"format-inference-report" desc:"print format inference report to stdout"`
	SymbolicTrace      bool   `flag:"symbolic-trace"          desc:"enable symbolic reconstruction"`
	ShowConcrete       bool   `flag:"show-concrete"           desc:"show concrete values alongside symbolic output"`
	ShowProvenance     bool   `flag:"show-provenance"         desc:"include full dependency graph in report"`
	TermReport         string `flag:"term-report"             desc:"write symbolic term report to file"`
	DetectCrypto       bool   `flag:"detect-crypto"           desc:"auto-detect crypto operations (default: true)"`
}

func defaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		MaxSuggestions: 10,
		LiveHistory:    2000,
		MinComponent:   2,
		MaxComponents:  10,
		Confidence:     "MEDIUM",
		DetectCrypto:   true,
	}
}

// RunE runs the monitor subcommand.
//
//nolint:gocyclo // This command intentionally orchestrates multiple modes in one entrypoint.
func (r *MonitorConfig) RunE(cmd *cobra.Command, args []string) error {
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
		if m != nil {
			m.Stats().EndTime = time.Now()
			fmt.Fprintln(os.Stderr, m.Stats().JSON())
		}

		os.Exit(0)
	}()

	specPath := args[0]

	role, _ := cmd.Root().Flags().GetString("role")
	decompose, _ := cmd.Root().Flags().GetBool("decompose")
	defines, _ := cmd.Root().Flags().GetStringSlice("defines")
	verbose, _ := cmd.Root().Flags().GetBool("verbose")

	// Parse main monitoring rules
	_, _, decompRules, err := ProcessRules(specPath, role, decompose, defines)
	if err != nil {
		return err
	}

	// Open input (file, stdin, or host:port).
	eventSource, err := openInputReader(r.In)
	if err != nil {
		return fmt.Errorf("cannot open input: %w", err)
	}
	defer eventSource.Close()

	// Create the main monitor and configure error display behavior.
	m, err = monitor.NewMonitor(decompRules)
	if err != nil {
		return fmt.Errorf("cannot create monitor: %w", err)
	}
	if r.Live {
		// Live UI mode is a separate path (Task 4).
		return runLiveMonitor(r, m, specPath, eventSource, role, decompose, defines, pid)
	}
	// Choose which output mode is active (compact/verbose, progress, infer, symbolic).
	symbolicEnabled := r.SymbolicTrace
	inferEnabled := r.InferFormats && !symbolicEnabled
	analysisMode := inferEnabled || symbolicEnabled
	progressEnabled := r.Progress && !verbose && !inferEnabled && !symbolicEnabled
	var progressErrLine atomic.Int64
	viewOpts := monitorViewOptions{
		showAllEvents:  r.ShowAll,
		showAllCfgs:    r.ShowAllCfgs,
		traceConfig:    r.TraceConfig,
		maxSuggestions: r.MaxSuggestions,
	}
	printProgressError := func() error {
		line := progressErrLine.Load()
		if line == 0 {
			return nil
		}
		headline := "✗ ERROR"
		if !color.NoColor {
			headline = color.New(color.FgRed, color.Bold).Sprint(headline)
		}
		fmt.Printf("\n%s Monitoring failed at line %d\n", headline, line)
		fmt.Println("  Run again without --progress to see full error details.")
		return monitor.ErrNoApplicableRule
	}
	inferOpts := inferOptions{
		minComponentLength: r.MinComponent,
		maxComponents:      r.MaxComponents,
		confidenceLevel:    r.Confidence,
	}
	detectCrypto := true
	if cmd.Flags().Changed("detect-crypto") {
		detectCrypto = r.DetectCrypto
	}
	symbolicOpts := symbolicOptions{
		showConcrete:   r.ShowConcrete || verbose,
		showProvenance: r.ShowProvenance,
		detectCrypto:   detectCrypto,
	}

	if r.RewriteWith != "" {
		// Rewrite mode: pre-trace goes directly to main monitor, live input goes through rewriter.
		// Integrated rewrite mode: first process pre-trace directly to main monitor,
		// then feed live input through the rewriter and into the main monitor.
		rewriteRules, _, _, err := ProcessRules(r.RewriteWith, role, decompose, defines)
		if err != nil {
			return fmt.Errorf("cannot process rewrite rules: %w", err)
		}

		count := 1
		var collected []eventInfo
		var inferState inferStreamState
		start := time.Now()
		var loader *loadingIndicator
		if analysisMode {
			loader = startLoadingIndicator(!quiet, "Started analysis...")
		}
		if !quiet && !progressEnabled {
			if !analysisMode {
				printHeader(startHeader(specPath, len(m.Configs()), analysisMode))
				fmt.Println()
			}
		}

		preTraceTotal := 0
		liveTotal := 0
		if progressEnabled {
			loader := startLoadingIndicator(!quiet, "Preparing Progress Bars...")
			if r.PreTrace != "" && isFileInput(r.PreTrace) {
				preTraceTotal, err = countParsedEvents(r.PreTrace)
				if err != nil || preTraceTotal <= 0 {
					preTraceTotal, _ = countLines(r.PreTrace)
				}
			}
			if isFileInput(r.In) {
				liveTotal, _ = countLines(r.In)
			}
			stopLoadingIndicator(loader)
		}

		// 1) Pre-trace to main monitor (no rewrite).
		if r.PreTrace != "" {
			preTrace, err := os.Open(r.PreTrace)
			if err != nil {
				return fmt.Errorf("cannot open pre-trace file: %w", err)
			}
			defer preTrace.Close()

			events := monitor.ParseEvents(preTrace, pid)
			_, consumedPre, preErrs := m.ProcessEvents(events, false, pid)
			// Inference/symbolic collects events; progress shows a bar; otherwise print.
			switch {
			case inferEnabled:
				count = streamInferredEvents(consumedPre, count, verbose, inferOpts, &inferState, &loader)
			case symbolicEnabled:
				var infos []eventInfo
				infos, count = collectEvents(consumedPre, count)
				collected = append(collected, infos...)
			case progressEnabled && isFileInput(r.PreTrace):
				progress := newProgress("Pre-Trace:", preTraceTotal)
				count = runProgress(consumedPre, progress, count, quiet, verbose)
			default:
				for event := range consumedPre {
					printEventLine(quiet, verbose, count, event)
					count++
				}
			}
			if err := handleProcessFailure(preErrs, m, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
				return err
			}
		}

		// 2) Live events: rewriter -> main monitor via channel.
		rewriter, err := monitor.NewMonitor(rewriteRules)
		if err != nil {
			return fmt.Errorf("cannot create rewrite monitor: %w", err)
		}
		rewriterEvents := monitor.ParseEvents(eventSource, pid)
		outs, _, rewriteErrs := rewriter.ProcessEvents(rewriterEvents, true, pid)
		_, consumedEvents, liveErrs := m.ProcessEvents(outs, false, pid)

		// Same output handling as pre-trace.
		switch {
		case inferEnabled:
			count = streamInferredEvents(consumedEvents, count, verbose, inferOpts, &inferState, &loader)
		case symbolicEnabled:
			var infos []eventInfo
			infos, count = collectEvents(consumedEvents, count)
			collected = append(collected, infos...)
		case progressEnabled && isFileInput(r.In):
			progress := newProgress("Live Trace:", liveTotal)
			count = runProgress(consumedEvents, progress, count, quiet, verbose)
		default:
			for event := range consumedEvents {
				printEventLine(quiet, verbose, count, event)
				count++
			}
		}
		if err := handleProcessFailure(rewriteErrs, rewriter, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
			return err
		}
		if err := handleProcessFailure(liveErrs, m, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
			if progressEnabled {
				if progressErr := printProgressError(); progressErr != nil {
					return progressErr
				}
			}
			return err
		}

		emitAnalysisOutput(symbolicEnabled, inferEnabled, quiet, collected, symbolicOpts, r.TermReport, &inferState, r.FormatReport, r.FormatReportStdout, loader)
		if !quiet && !progressEnabled {
			fmt.Println()
			printHeader(compactHeader(specPath, count-1, len(m.Configs()), start, analysisMode))
		}
		return nil
	}

	// Non-rewrite mode: standard input handling.
	count := 1
	var collected []eventInfo
	var inferState inferStreamState
	start := time.Now()
	var loader *loadingIndicator
	if analysisMode {
		loader = startLoadingIndicator(!quiet, "Started analysis...")
	}
	if !quiet && !progressEnabled {
		if !analysisMode {
			printHeader(startHeader(specPath, len(m.Configs()), analysisMode))
			fmt.Println()
		}
	}

	switch {
	case inferEnabled || symbolicEnabled:
		// Inference/symbolic needs full event collection first.
		if r.PreTrace != "" && isFileInput(r.PreTrace) {
			preTrace, err := os.Open(r.PreTrace)
			if err != nil {
				return fmt.Errorf("cannot open pre-trace file: %w", err)
			}
			defer preTrace.Close()
			events := monitor.ParseEvents(preTrace, pid)
			_, consumedPre, preErrs := m.ProcessEvents(events, false, pid)
			if inferEnabled {
				count = streamInferredEvents(consumedPre, count, verbose, inferOpts, &inferState, &loader)
			} else {
				var infos []eventInfo
				infos, count = collectEvents(consumedPre, count)
				collected = append(collected, infos...)
			}
			if err := handleProcessFailure(preErrs, m, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
				return err
			}
		}

		events := monitor.ParseEvents(eventSource, pid)
		_, consumed, errs := m.ProcessEvents(events, false, pid)
		if inferEnabled {
			count = streamInferredEvents(consumed, count, verbose, inferOpts, &inferState, &loader)
		} else {
			var infos []eventInfo
			infos, count = collectEvents(consumed, count)
			collected = append(collected, infos...)
		}
		if err := handleProcessFailure(errs, m, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
			return err
		}
	case progressEnabled:
		// Progress mode: count lines and render bar while consuming events.
		preTraceTotal := 0
		liveTotal := 0
		loader := startLoadingIndicator(!quiet, "Preparing Progress Bars...")
		if r.PreTrace != "" && isFileInput(r.PreTrace) {
			preTraceTotal, _ = countLines(r.PreTrace)
		}
		if isFileInput(r.In) {
			liveTotal, _ = countLines(r.In)
		}
		stopLoadingIndicator(loader)

		if r.PreTrace != "" && isFileInput(r.PreTrace) {
			preTrace, err := os.Open(r.PreTrace)
			if err != nil {
				return fmt.Errorf("cannot open pre-trace file: %w", err)
			}
			defer preTrace.Close()
			events := monitor.ParseEvents(preTrace, pid)
			_, consumedPre, preErrs := m.ProcessEvents(events, false, pid)
			progress := newProgress("Pre-Trace:", preTraceTotal)
			count = runProgress(consumedPre, progress, count, quiet, verbose)
			if err := handleProcessFailure(preErrs, m, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
				if progressErr := printProgressError(); progressErr != nil {
					return progressErr
				}
				return err
			}
		}

		if isFileInput(r.In) {
			events := monitor.ParseEvents(eventSource, pid)
			_, consumed, errs := m.ProcessEvents(events, false, pid)
			progress := newProgress("Live Trace:", liveTotal)
			count = runProgress(consumed, progress, count, quiet, verbose)
			if err := handleProcessFailure(errs, m, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
				if progressErr := printProgressError(); progressErr != nil {
					return progressErr
				}
				return err
			}
		} else {
			events := monitor.ParseEvents(eventSource, pid)
			_, consumed, errs := m.ProcessEvents(events, false, pid)
			for event := range consumed {
				printEventLine(quiet, verbose, count, event)
				count++
			}
			if err := handleProcessFailure(errs, m, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
				if progressErr := printProgressError(); progressErr != nil {
					return progressErr
				}
				return err
			}
		}
	default:
		// Default mode: stream events and print each line.
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

		events := monitor.ParseEvents(source, pid)
		_, consumed, errs := m.ProcessEvents(events, false, pid)

		for event := range consumed {
			printEventLine(quiet, verbose, count, event)
			count++
		}
		if err := handleProcessFailure(errs, m, quiet, progressEnabled, &progressErrLine, viewOpts); err != nil {
			return err
		}
	}

	emitAnalysisOutput(symbolicEnabled, inferEnabled, quiet, collected, symbolicOpts, r.TermReport, &inferState, r.FormatReport, r.FormatReportStdout, loader)
	if !quiet && !progressEnabled {
		fmt.Println()
		printHeader(compactHeader(specPath, count-1, len(m.Configs()), start, analysisMode))
	}
	return nil
}

func printEventLine(quiet, verbose bool, count int, event term.Term) {
	// Single event output line: compact by default, verbose when requested.
	if quiet {
		return
	}

	if verbose {
		fmt.Printf("%s %4d  %s\n", successMarker(), count, formatVerboseEvent(event))
		return
	}

	fmt.Printf("%s %4d  %s\n", successMarker(), count, formatCompactEvent(event))
}

type monitorViewOptions struct {
	showAllEvents  bool
	showAllCfgs    bool
	traceConfig    int
	maxSuggestions int
}

func waitProcessError(errs <-chan *monitor.ProcessError) *monitor.ProcessError {
	if errs == nil {
		return nil
	}
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func handleProcessFailure(errs <-chan *monitor.ProcessError, m *monitor.Monitor, quiet, progress bool, progressErrLine *atomic.Int64, opts monitorViewOptions) error {
	procErr := waitProcessError(errs)
	if procErr == nil {
		return nil
	}
	if progress {
		progressErrLine.CompareAndSwap(0, int64(procErr.Line))
		return procErr.Err
	}
	if quiet {
		return procErr.Err
	}
	fmt.Println(formatErrorLineMarker(procErr.Line, procErr.Event))
	fmt.Println()
	details := m.BuildNoApplicableRuleDetails(procErr.Event, procErr.Line, opts.showAllCfgs, opts.traceConfig)
	fmt.Print(formatNoApplicableRule(details, opts.showAllEvents, opts.maxSuggestions))
	return procErr.Err
}

func formatErrorLineMarker(line int, event term.Term) string {
	marker := "✗"
	if !color.NoColor {
		marker = color.New(color.FgRed).Sprint("✗")
	}
	return fmt.Sprintf("%s %4d  %s", marker, line, event)
}

func formatNoApplicableRule(details monitor.NoApplicableRuleDetails, showAll bool, maxSuggestions int) string {
	var b strings.Builder
	headline := "✗ ERROR: Event Processing Failed"
	if !color.NoColor {
		headline = color.New(color.FgRed, color.Bold).Sprint(headline)
	}
	fmt.Fprintln(&b, headline)
	fmt.Fprintf(&b, "  Event: %s\n", details.Event)
	if details.Line > 0 {
		fmt.Fprintf(&b, "  Line: %d\n", details.Line)
	}
	fmt.Fprintf(&b, "  Reason: %s\n", details.Reason)
	fmt.Fprintln(&b)

	if details.ConfigCount > 1 {
		fmt.Fprintf(&b, "WARNING: Multiple Configurations Detected (%d)\n", details.ConfigCount)
		fmt.Fprintln(&b, "  The specification has branched into multiple possible states.")
		fmt.Fprintln(&b, "  Allowed events differ by configuration.")
	}
	if details.MissingTraceConfig > 0 {
		fmt.Fprintf(&b, "\nWARNING: Config #%d not found; showing all configs\n", details.MissingTraceConfig)
	}

	for _, cfg := range details.Configs {
		if details.ConfigCount > 1 {
			fmt.Fprintf(&b, "\nConfig #%d:\n", cfg.Index)
		}
		formatPossibleEvents(&b, cfg.Events, showAll, maxSuggestions)
	}

	if details.ShowTraceConfigHint {
		fmt.Fprintln(&b, "Use --trace-config=N to follow specific configuration")
	}
	if details.ShowAllConfigsHint {
		fmt.Fprintln(&b, "Use --show-all-configs to see all possible events per configuration")
	}

	return b.String()
}

func formatPossibleEvents(b *strings.Builder, events []monitor.ExpectedEvent, showAll bool, maxPerGroup int) {
	if showAll || maxPerGroup <= 0 {
		maxPerGroup = len(events)
	}

	groups := groupExpectedEvents(events)
	if len(groups) == 0 {
		fmt.Fprintln(b, "No expected events available.")
		return
	}

	total := len(events)
	if !showAll && total > maxPerGroup {
		fmt.Fprintf(b, "Expected Events (showing %d of %d, grouped by event name):\n\n", maxPerGroup, total)
	} else {
		fmt.Fprintf(b, "Expected Events (showing %d of %d, grouped by event name):\n\n", total, total)
	}

	truncated := false
	for _, g := range groups {
		fmt.Fprintf(b, "%s/%d:\n", g.Name, g.Arity)
		limit := len(g.Items)
		if !showAll && limit > maxPerGroup {
			limit = maxPerGroup
		}
		for i := 0; i < limit; i++ {
			fmt.Fprintf(b, "  [%s] %s\n", g.Items[i].RuleName, g.Items[i].Term)
		}
		if limit < len(g.Items) {
			fmt.Fprintf(b, "  ... (%d more)\n", len(g.Items)-limit)
			truncated = true
		}
		fmt.Fprintln(b)
	}
	if truncated {
		fmt.Fprintf(b, "Use --show-all-events to see all %d possibilities\n", total)
		fmt.Fprintln(b, "Use --debug for full trace and rule details")
	}
}

type expectedEventGroup struct {
	Name  string
	Arity int
	Items []monitor.ExpectedEvent
}

func groupExpectedEvents(events []monitor.ExpectedEvent) []expectedEventGroup {
	grouped := make(map[string]*expectedEventGroup)
	for _, ev := range events {
		key := fmt.Sprintf("%s/%d", ev.Name, ev.Arity)
		if grouped[key] == nil {
			grouped[key] = &expectedEventGroup{Name: ev.Name, Arity: ev.Arity}
		}
		grouped[key].Items = append(grouped[key].Items, ev)
	}

	var out []expectedEventGroup
	for _, group := range grouped {
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Arity < out[j].Arity
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func successMarker() string {
	if color.NoColor {
		return "✓"
	}
	return color.New(color.FgGreen).Sprint("✓")
}

func compactHeader(specPath string, count, configs int, start time.Time, analysisMode bool) string {
	// Compact status header with rate and elapsed time.
	elapsed := time.Since(start)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(count) / elapsed.Seconds()
	}
	label := "Monitoring ended"
	if analysisMode {
		label = "Analysis finished"
	}
	content := fmt.Sprintf(
		"%s: %s | Events: %d | Configs: %d | Rate: %.1f/s | Time: %s",
		label,
		specPath,
		count,
		configs,
		rate,
		elapsed.Round(100*time.Millisecond),
	)
	return formatHeaderBox(content)
}

func formatCompactEvent(t term.Term) string {
	// Compact rendering of a term while preserving call/return structure.
	fn, err := term.AsFunction(t)
	if err != nil || fn == nil {
		return formatCompactTerm(t)
	}

	if fn.Name == term.PairFunctionName && len(fn.Args) == 2 {
		if call, err := term.AsFunction(fn.Args[0]); err == nil && call != nil {
			return fmt.Sprintf("%s → %s", formatCompactCall(call.Name, call.Args), formatCompactTerm(fn.Args[1]))
		}
	}

	return formatCompactCall(fn.Name, fn.Args)
}

func formatVerboseEvent(t term.Term) string {
	// Full rendering of a term while preserving call/return structure.
	fn, err := term.AsFunction(t)
	if err != nil || fn == nil {
		return formatVerboseTerm(t)
	}

	if fn.Name == term.PairFunctionName && len(fn.Args) == 2 {
		if call, err := term.AsFunction(fn.Args[0]); err == nil && call != nil {
			return fmt.Sprintf("%s → %s", formatVerboseCall(call.Name, call.Args), formatVerboseTerm(fn.Args[1]))
		}
	}

	return formatVerboseTerm(fn)
}

func formatCompactCall(name string, args []term.Term) string {
	// Compact rendering of a function call (with colored name).
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
	// Compact term formatting (short bytes, quoted strings, etc.).
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
	// Verbose term formatting (full values).
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
	// Verbose rendering of a function call.
	if name == term.PairFunctionName {
		return formatVerbosePair(args)
	}
	if args == nil {
		return fmt.Sprintf("%s()", name)
	}

	var b strings.Builder
	b.WriteString(colorEventName(name))
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
	// Compact pair formatting: <a, b, ...>.
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
	// Verbose pair formatting: <a, b, ...>.
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

type progressState struct {
	label string
	total int
	start time.Time
}

func newProgress(label string, total int) progressState {
	// Progress bar state initializer.
	return progressState{label: label, total: total, start: time.Now()}
}

func runProgress(consumed <-chan term.Term, progress progressState, count int, quiet, verbose bool) int {
	// Consume events while rendering a progress bar for batch inputs.
	if progress.total <= 0 {
		for event := range consumed {
			printEventLine(quiet, verbose, count, event)
			count++
		}
		return count
	}

	fmt.Println()
	if progress.label != "" {
		fmt.Println(progress.label)
	}
	current := 0
	maxLineLen := 0
	for range consumed {
		current++
		count++
		line := renderProgress(progress, current)
		if len(line) > maxLineLen {
			maxLineLen = len(line)
		}
		fmt.Printf("\r%-*s", maxLineLen, line)
	}
	finalLine := renderProgress(progress, current)
	if len(finalLine) > maxLineLen {
		maxLineLen = len(finalLine)
	}
	fmt.Printf("\r%-*s\n", maxLineLen, finalLine)
	return count
}

func renderProgress(progress progressState, current int) string {
	// Render a compact progress line with bar, elapsed time, and ETA.
	elapsed := time.Since(progress.start)
	if elapsed < 0 {
		elapsed = 0
	}

	ratio := 0.0
	if progress.total > 0 {
		ratio = float64(current) / float64(progress.total)
		if ratio > 1 {
			ratio = 1
		}
	}
	percent := int(ratio * 100)

	const barWidth = 20
	filled := int(ratio * barWidth)
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	eta := time.Duration(0)
	if current > 0 && progress.total > current {
		perItem := elapsed / time.Duration(current)
		eta = perItem * time.Duration(progress.total-current)
	}
	elapsedText := fmt.Sprintf("%6s", elapsed.Round(100*time.Millisecond))
	etaText := fmt.Sprintf("%6s", eta.Round(100*time.Millisecond))

	return fmt.Sprintf(
		"[%s] %d/%d %d%% in %s, ETA %s",
		bar,
		current,
		progress.total,
		percent,
		elapsedText,
		etaText,
	)
}

func collectEvents(consumed <-chan term.Term, start int) ([]eventInfo, int) {
	// Convert an event stream into eventInfo slices for inference/symbolic modes.
	var infos []eventInfo
	count := start
	for event := range consumed {
		if info, ok := buildEventInfo(count, event); ok {
			infos = append(infos, info)
		}
		count++
	}
	return infos, count
}

type inferStreamState struct {
	prevValues []valueRef
	inferences []inference
}

const inferredCommentColumn = 56

func formatInferenceNote(note string) string {
	if color.NoColor {
		return ">> " + note
	}
	return color.New(color.FgBlack, color.BgHiYellow, color.Bold).Sprint(" " + note + " ")
}

func streamInferredEvents(consumed <-chan term.Term, start int, verbose bool, opts inferOptions, state *inferStreamState, loader **loadingIndicator) int {
	count := start
	for event := range consumed {
		if info, ok := buildEventInfo(count, event); ok {
			notes, inferred, refs := inferEventFormats(info, state.prevValues, opts)
			state.prevValues = append(state.prevValues, refs...)
			state.inferences = append(state.inferences, inferred...)
			writeInferredEventLines(info, notes, verbose, loader)
		}
		count++
	}
	return count
}

func writeInferredEventLines(ev eventInfo, notes []string, verbose bool, loader **loadingIndicator) {
	line := formatCompactEvent(ev.raw)
	if verbose {
		line = formatVerboseEvent(ev.raw)
	}
	prefix := fmt.Sprintf("%s %4d  %s", successMarker(), ev.index, line)
	lines := []string{prefix}
	if len(notes) > 0 {
		commentColumn := max(visibleTextWidth(prefix)+2, inferredCommentColumn)
		pad := commentColumn - visibleTextWidth(prefix)
		if pad < 1 {
			pad = 1
		}
		lines[0] = prefix + strings.Repeat(" ", pad) + formatInferenceNote(notes[0])
		padding := strings.Repeat(" ", commentColumn)
		for _, note := range notes[1:] {
			lines = append(lines, padding+formatInferenceNote(note))
		}
	}
	writeStreamLines(lines, loader)
}

func writeStreamLines(lines []string, loader **loadingIndicator) {
	if loader != nil && *loader != nil {
		stopLoadingIndicator(*loader)
		*loader = nil
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for _, line := range lines {
		_, _ = w.WriteString(line)
		_ = w.WriteByte('\n')
	}
}

func emitAnalysisOutput(
	symbolicEnabled bool,
	inferEnabled bool,
	quiet bool,
	collected []eventInfo,
	symbolicOpts symbolicOptions,
	termReport string,
	inferState *inferStreamState,
	formatReport string,
	formatReportStdout bool,
	loader *loadingIndicator,
) {
	switch {
	case symbolicEnabled && !quiet:
		writeSymbolicOutput(collected, symbolicOpts, termReport, loader)
	case inferEnabled && !quiet:
		finalizeInferredOutput(inferState, formatReport, formatReportStdout, loader)
	default:
		stopLoadingIndicator(loader)
	}
}

func finalizeInferredOutput(state *inferStreamState, reportPath string, reportStdout bool, loader *loadingIndicator) {
	stopLoadingIndicator(loader)
	if state == nil {
		return
	}
	report := ""
	if reportPath != "" || reportStdout {
		report = buildFormatReport(state.inferences)
	}
	if reportPath != "" {
		writeReportFile(reportPath, report, "format report")
	}
	if reportStdout {
		fmt.Println()
		fmt.Print(report)
	}
}

func writeReportFile(path, report, label string) {
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", label, err)
	}
}

var ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func visibleTextWidth(s string) int {
	return len([]rune(ansiEscapeRE.ReplaceAllString(s, "")))
}

func writeSymbolicOutput(events []eventInfo, opts symbolicOptions, reportPath string, loader *loadingIndicator) {
	// Print symbolic trace output and emit the term report.
	symEvents, vars, computed := buildSymbolic(events, opts)
	report := buildSymbolicReport(symEvents, vars, computed, opts)
	if reportPath != "" {
		writeReportFile(reportPath, report, "term report")
	}
	writeLinesGradually(renderSymbolicLines(symEvents, opts), loader)
}

func writeLinesGradually(lines []string, loader *loadingIndicator) {
	// Flush each line so analysis output appears progressively instead of one big dump.
	stopLoadingIndicator(loader)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for _, line := range lines {
		_, _ = w.WriteString(line)
		_ = w.WriteByte('\n')
		_ = w.Flush()
	}
}

func formatHeaderBox(content string) string {
	// Draw a simple box around a single header line.
	width := len([]rune(content)) + 2
	top := "┌" + strings.Repeat("─", width) + "┐"
	mid := fmt.Sprintf("│ %s │", content)
	bot := "└" + strings.Repeat("─", width) + "┘"
	return strings.Join([]string{top, mid, bot}, "\n")
}

func printHeader(header string) {
	// Print a boxed header line-by-line.
	for _, line := range strings.Split(header, "\n") {
		fmt.Println(line)
	}
}

type loadingIndicator struct {
	stop chan struct{}
	done chan struct{}
}

func startLoadingIndicator(enabled bool, title string) *loadingIndicator {
	// Show a simple spinner while long-running startup/analysis work happens.
	if !enabled {
		return nil
	}

	li := &loadingIndicator{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	fmt.Println()
	go func() {
		defer close(li.done)
		frames := []string{"|", "/", "-", `\`}
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()

		i := 0
		for {
			line := fmt.Sprintf("\r%s", frames[i%len(frames)])
			if strings.TrimSpace(title) != "" {
				line = fmt.Sprintf("\r%s %s", frames[i%len(frames)], title)
			}
			fmt.Fprint(os.Stdout, line)
			i++
			select {
			case <-li.stop:
				fmt.Fprint(os.Stdout, "\r\033[2K")
				return
			case <-ticker.C:
			}
		}
	}()
	return li
}

func stopLoadingIndicator(li *loadingIndicator) {
	if li == nil {
		return
	}
	close(li.stop)
	<-li.done
}

func startHeader(specPath string, configs int, analysisMode bool) string {
	// Build the mode-aware start header.
	_ = configs
	label := "Monitoring started"
	if analysisMode {
		label = "Started analysis"
	}
	content := fmt.Sprintf("%s: %s", label, specPath)
	return formatHeaderBox(content)
}

func colorEventName(name string) string {
	// Assign colors to event names in first-seen order (dictionary-style).
	if color.NoColor {
		return name
	}

	key := strings.ToLower(name)
	eventColorMu.Lock()
	idx, ok := eventColorByName[key]
	if !ok {
		idx = len(eventColorByName) % len(eventColorPalette)
		eventColorByName[key] = idx
	}
	eventColorMu.Unlock()

	return eventColorPalette[idx].Sprint(name)
}

// NewMonitorCmd creates a new command for the monitor subcommand.
func NewMonitorCmd() *cobra.Command {
	monitorConfig := defaultMonitorConfig()

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
