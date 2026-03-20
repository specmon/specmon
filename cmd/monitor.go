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

// RunE runs the monitor subcommand.
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
	m.SetShowAllEvents(r.ShowAll)
	m.SetTraceConfig(r.TraceConfig)
	m.SetShowAllConfigs(r.ShowAllCfgs)
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
	if progressEnabled {
		m.SetErrorHandler(func(line int, _ term.Term, _ string) {
			progressErrLine.CompareAndSwap(0, int64(line))
		})
	}
	printProgressError := func() bool {
		line := progressErrLine.Load()
		if line == 0 {
			return false
		}
		headline := "✗ ERROR"
		if !color.NoColor {
			headline = color.New(color.FgRed, color.Bold).Sprint(headline)
		}
		fmt.Printf("\n%s Monitoring failed at line %d\n", headline, line)
		fmt.Println("  Run again without --progress to see full error details.")
		return true
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
				liveTotal, err = countRewriteOutputs(r.In, r.RewriteWith, role, decompose, defines, r)
				if err != nil || liveTotal <= 0 {
					liveTotal, _ = countLines(r.In)
				}
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
			_, consumedPre := m.ProcessEvents(events, false, pid)
			// Inference/symbolic collects events; progress shows a bar; otherwise print.
			if inferEnabled || symbolicEnabled {
				var infos []eventInfo
				infos, count = collectEvents(consumedPre, count)
				collected = append(collected, infos...)
			} else if progressEnabled && isFileInput(r.PreTrace) {
				progress := newProgress("Pre-Trace:", preTraceTotal)
				count = runProgress(consumedPre, progress, count, start, quiet, verbose, specPath, len(m.Configs()))
			} else {
				for c := range consumedPre {
					printEventLine(quiet, verbose, specPath, start, count, len(m.Configs()), c.Term)
					c.Done()
					count++
				}
			}
		}

		// 2) Live events: rewriter -> main monitor via channel.
		rewriter, err := monitor.NewMonitor(rewriteRules)
		if err != nil {
			return fmt.Errorf("cannot create rewrite monitor: %w", err)
		}
		rewriter.SetShowAllEvents(r.ShowAll)
		rewriter.SetTraceConfig(r.TraceConfig)
		rewriter.SetShowAllConfigs(r.ShowAllCfgs)
		if progressEnabled {
			rewriter.SetErrorHandler(func(line int, _ term.Term, _ string) {
				progressErrLine.CompareAndSwap(0, int64(line))
			})
		}

		rewriterEvents := monitor.ParseEvents(eventSource, pid)
		outs, _ := rewriter.ProcessEvents(rewriterEvents, true, pid)
		_, consumedEvents := m.ProcessEvents(outs, false, pid)

		// Same output handling as pre-trace.
		if inferEnabled || symbolicEnabled {
			var infos []eventInfo
			infos, count = collectEvents(consumedEvents, count)
			collected = append(collected, infos...)
		} else if progressEnabled && isFileInput(r.In) {
			progress := newProgress("Live Trace:", liveTotal)
			count = runProgress(consumedEvents, progress, count, start, quiet, verbose, specPath, len(m.Configs()))
			if printProgressError() {
				return nil
			}
		} else {
			for c := range consumedEvents {
				printEventLine(quiet, verbose, specPath, start, count, len(m.Configs()), c.Term)
				c.Done()
				count++
			}
		}

		// Emit inference/symbolic reports at the end of processing.
		if symbolicEnabled && !quiet {
			writeSymbolicOutput(collected, symbolicOpts, r.TermReport, loader)
		} else if inferEnabled && !quiet {
			writeInferredOutput(collected, inferOpts, verbose, r.FormatReport, r.FormatReportStdout, loader)
		} else {
			stopLoadingIndicator(loader)
		}
		if !quiet && !progressEnabled {
			fmt.Println()
			printHeader(compactHeader(specPath, count-1, len(m.Configs()), start, analysisMode))
		}
		return nil
	}

	// Non-rewrite mode: standard input handling.
	count := 1
	var collected []eventInfo
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

	if inferEnabled || symbolicEnabled {
		// Inference/symbolic needs full event collection first.
		if r.PreTrace != "" && isFileInput(r.PreTrace) {
			preTrace, err := os.Open(r.PreTrace)
			if err != nil {
				return fmt.Errorf("cannot open pre-trace file: %w", err)
			}
			defer preTrace.Close()
			events := monitor.ParseEvents(preTrace, pid)
			_, consumedPre := m.ProcessEvents(events, false, pid)
			var infos []eventInfo
			infos, count = collectEvents(consumedPre, count)
			collected = append(collected, infos...)
		}

		if isFileInput(r.In) {
			events := monitor.ParseEvents(eventSource, pid)
			_, consumed := m.ProcessEvents(events, false, pid)
			var infos []eventInfo
			infos, count = collectEvents(consumed, count)
			collected = append(collected, infos...)
		} else {
			events := monitor.ParseEvents(eventSource, pid)
			_, consumed := m.ProcessEvents(events, false, pid)
			var infos []eventInfo
			infos, count = collectEvents(consumed, count)
			collected = append(collected, infos...)
		}
	} else if progressEnabled {
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
			_, consumedPre := m.ProcessEvents(events, false, pid)
			progress := newProgress("Pre-Trace:", preTraceTotal)
			count = runProgress(consumedPre, progress, count, start, quiet, verbose, specPath, len(m.Configs()))
			if printProgressError() {
				return nil
			}
		}

		if isFileInput(r.In) {
			events := monitor.ParseEvents(eventSource, pid)
			_, consumed := m.ProcessEvents(events, false, pid)
			progress := newProgress("Live Trace:", liveTotal)
			count = runProgress(consumed, progress, count, start, quiet, verbose, specPath, len(m.Configs()))
			if printProgressError() {
				return nil
			}
		} else {
			events := monitor.ParseEvents(eventSource, pid)
			_, consumed := m.ProcessEvents(events, false, pid)
			for c := range consumed {
				printEventLine(quiet, verbose, specPath, start, count, len(m.Configs()), c.Term)
				c.Done()
				count++
			}
			if printProgressError() {
				return nil
			}
		}
	} else {
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
		_, consumed := m.ProcessEvents(events, false, pid)

		for c := range consumed {
			printEventLine(quiet, verbose, specPath, start, count, len(m.Configs()), c.Term)
			c.Done()
			count++
		}
	}

	// Emit inference/symbolic reports at the end of processing.
	if symbolicEnabled && !quiet {
		writeSymbolicOutput(collected, symbolicOpts, r.TermReport, loader)
	} else if inferEnabled && !quiet {
		writeInferredOutput(collected, inferOpts, verbose, r.FormatReport, r.FormatReportStdout, loader)
	} else {
		stopLoadingIndicator(loader)
	}
	if !quiet && !progressEnabled {
		fmt.Println()
		printHeader(compactHeader(specPath, count-1, len(m.Configs()), start, analysisMode))
	}

	return nil
}

func printEventLine(quiet, verbose bool, specPath string, start time.Time, count, configs int, event term.Term) {
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
	// Compact rendering of a term, unwrapping pair-wrapped events.
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
	// Full rendering of a term (no truncation), unwrapping pair-wrapped events.
	fn, err := term.AsFunction(t)
	if err != nil || fn == nil {
		return formatVerboseTerm(t)
	}

	if fn.Name == term.PairFunctionName && len(fn.Args) == 2 {
		if call, err := term.AsFunction(fn.Args[0]); err == nil && call != nil {
			args := append([]term.Term{}, call.Args...)
			args = append(args, fn.Args[1])
			return formatVerboseCall(call.Name, args)
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

func runProgress(consumed <-chan *monitor.ConsumedEvent, progress progressState, count int, start time.Time, quiet, verbose bool, specPath string, configs int) int {
	// Consume events while rendering a progress bar for batch inputs.
	if progress.total <= 0 {
		for c := range consumed {
			printEventLine(quiet, verbose, specPath, start, count, configs, c.Term)
			c.Done()
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
	for c := range consumed {
		current++
		count++
		line := renderProgress(progress, current)
		if len(line) > maxLineLen {
			maxLineLen = len(line)
		}
		fmt.Printf("\r%-*s", maxLineLen, line)
		c.Done()
	}
	finalLine := renderProgress(progress, current)
	if len(finalLine) > maxLineLen {
		maxLineLen = len(finalLine)
	}
	fmt.Printf("\r%-*s\n", maxLineLen, finalLine)
	return count
}

func renderProgress(progress progressState, current int) string {
	// Render a compact progress line with bar: "[bar] current/total percent in elapsed".
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

	return fmt.Sprintf("[%s] %d/%d %d%% in %s", bar, current, progress.total, percent, elapsed.Round(100*time.Millisecond))
}

func collectEvents(consumed <-chan *monitor.ConsumedEvent, start int) ([]eventInfo, int) {
	// Convert an event stream into eventInfo slices for inference/symbolic modes.
	var infos []eventInfo
	count := start
	for c := range consumed {
		if info, ok := buildEventInfo(count, c.Term); ok {
			infos = append(infos, info)
		}
		c.Done()
		count++
	}
	return infos, count
}

func writeInferredOutput(events []eventInfo, opts inferOptions, verbose bool, reportPath string, reportStdout bool, loader *loadingIndicator) {
	// Print annotated events and emit the format inference report.
	annotations, inferences := inferFormats(events, opts)
	report := ""
	if reportPath != "" || reportStdout {
		report = buildFormatReport(inferences)
	}
	rendered := make([]string, len(events))
	maxPrefixWidth := 0
	for i, ev := range events {
		line := formatCompactEvent(ev.raw)
		if verbose {
			line = formatVerboseEvent(ev.raw)
		}
		prefix := fmt.Sprintf("%s %4d  %s", successMarker(), ev.index, line)
		rendered[i] = prefix
		if w := visibleTextWidth(prefix); w > maxPrefixWidth {
			maxPrefixWidth = w
		}
	}

	commentColumn := maxPrefixWidth + 2
	lines := make([]string, 0, len(events))
	for i, ev := range events {
		prefix := rendered[i]
		line := prefix
		if note, ok := annotations[ev.index]; ok {
			pad := commentColumn - visibleTextWidth(prefix)
			if pad < 1 {
				pad = 1
			}
			line += strings.Repeat(" ", pad) + strings.TrimLeft(note, " ")
		}
		lines = append(lines, line)
	}

	if reportPath != "" {
		if err := os.WriteFile(reportPath, []byte(report), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write format report: %v\n", err)
		}
	}
	writeLinesGradually(lines, loader)

	if reportStdout {
		fmt.Println()
		fmt.Print(report)
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
		if err := os.WriteFile(reportPath, []byte(report), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write term report: %v\n", err)
		}
	}
	writeLinesGradually(renderSymbolicLines(symEvents, opts), loader)
}

func writeLinesGradually(lines []string, loader *loadingIndicator) {
	// Flush each line so analysis output appears progressively instead of one big dump.
	stopLoadingIndicator(loader)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	delay := outputLineDelay(len(lines))
	for _, line := range lines {
		_, _ = w.WriteString(line)
		_ = w.WriteByte('\n')
		_ = w.Flush()
		if delay > 0 {
			time.Sleep(delay)
		}
	}
}

func outputLineDelay(n int) time.Duration {
	// Keep a slight pacing only on real terminals so replay is visually progressive.
	info, err := os.Stdout.Stat()
	if err != nil || (info.Mode()&os.ModeCharDevice) == 0 {
		return 0
	}
	switch {
	case n > 5000:
		return 200 * time.Microsecond
	case n > 1000:
		return 350 * time.Microsecond
	case n > 200:
		return 600 * time.Microsecond
	default:
		return time.Millisecond
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
