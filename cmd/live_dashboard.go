package cmd

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fatih/color"
	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
)

const (
	liveDefaultWidth       = 80
	liveMinWidth           = 60
	liveProgressBarWidth   = 20
	liveCompactPageSize    = 5
	liveDetailedPageSize   = 10
	liveEventAreaStartLine = 12
	liveTickInterval       = 200 * time.Millisecond
	liveMemRefreshInterval = 2 * time.Second
	livePausePollInterval  = 50 * time.Millisecond
	liveDefaultHistory     = 2000
)

type liveEventMsg struct {
	count   int
	compact string
	verbose string
	configs int
}

type liveTickMsg struct {
	time.Time
}

type liveDoneMsg struct{}

type liveErrorMsg struct {
	message string
	line    string
	event   string
	reason  string
	details []string
}

type liveModel struct {
	specPath     string
	start        time.Time
	pauseAt      time.Time
	pausedFor    time.Duration
	lastMemRead  time.Time
	count        int
	total        int
	configs      int
	entries      []liveEntry
	memMB        float64
	elapsed      time.Duration
	width        int
	height       int
	status       string
	quitReady    bool
	done         bool
	errMsg       string
	paused       bool
	details      bool
	verbose      bool
	pauseFlag    *uint32
	scrollOffset int
	viewOffset   int
	jumpMode     bool
	jumpBuf      string
	historyLimit int
	infoMsg      string
	errDetails   []string
}

type liveEntry struct {
	index   int
	compact string
	verbose string
}

func newLiveModel(specPath string, start time.Time, configs int, total int, pauseFlag *uint32, historyLimit int) liveModel {
	// Initialize the live dashboard state.
	return liveModel{
		specPath:     specPath,
		start:        start,
		lastMemRead:  start,
		total:        total,
		configs:      configs,
		status:       "Running",
		pauseFlag:    pauseFlag,
		historyLimit: historyLimit,
	}
}

func (m liveModel) Init() tea.Cmd {
	// Start periodic UI ticks.
	return liveTick()
}

//nolint:ireturn // Bubble Tea requires tea.Model as the Update return type.
func (m liveModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Handle key presses, ticks, and incoming events for the dashboard.
	switch v := msg.(type) {
	case tea.KeyMsg:
		switch v.String() {
		case "q", "ctrl+c":
			m.quitReady = true
			return m, tea.Quit
		case "j":
			if !m.jumpMode {
				m.jumpMode = true
				m.jumpBuf = ""
			}
		case "p":
			if !m.done && m.status != "Error" {
				m.paused = !m.paused
				if m.paused {
					m.status = "Paused"
					m.pauseAt = time.Now()
					atomic.StoreUint32(m.pauseFlag, 1)
				} else {
					m.status = "Running"
					if !m.pauseAt.IsZero() {
						m.pausedFor += time.Since(m.pauseAt)
						m.pauseAt = time.Time{}
					}
					atomic.StoreUint32(m.pauseFlag, 0)
				}
			}
		case "d":
			m.details = !m.details
		case "v":
			m.verbose = !m.verbose
		case "up":
			m.scrollOffset = min(m.scrollOffset+1, m.maxScrollOffset())
		case "down":
			m.scrollOffset = max(m.scrollOffset-1, 0)
		case "pgup":
			m.viewOffset = max(m.viewOffset-m.pageSize(), 0)
		case "pgdown":
			m.viewOffset += m.pageSize()
		case "enter":
			if m.jumpMode {
				m.jumpTo()
			}
		case "esc":
			m.jumpMode = false
			m.jumpBuf = ""
			m.infoMsg = ""
		default:
			if m.jumpMode {
				if v.Type == tea.KeyBackspace || v.Type == tea.KeyDelete {
					if len(m.jumpBuf) > 0 {
						m.jumpBuf = m.jumpBuf[:len(m.jumpBuf)-1]
					}
					break
				}
				if len(v.Runes) == 1 && v.Runes[0] >= '0' && v.Runes[0] <= '9' {
					m.jumpBuf += string(v.Runes[0])
				}
			}
		}
	case tea.WindowSizeMsg:
		m.width = v.Width
		m.height = v.Height
	case tea.MouseMsg:
		if v.Type == tea.MouseWheelUp || v.Type == tea.MouseWheelDown {
			absY := m.viewOffset + v.Y
			eventStart, eventEnd := m.eventAreaBounds()
			if absY >= eventStart && absY <= eventEnd {
				if v.Type == tea.MouseWheelUp {
					m.scrollOffset = min(m.scrollOffset+1, m.maxScrollOffset())
				} else {
					m.scrollOffset = max(m.scrollOffset-1, 0)
				}
			} else {
				if v.Type == tea.MouseWheelUp {
					m.viewOffset = max(m.viewOffset-1, 0)
				} else {
					m.viewOffset++
				}
			}
		}
	case liveEventMsg:
		m.count = v.count
		m.configs = v.configs
		m.addEntry(v.count, v.compact, v.verbose)
		m.infoMsg = ""
	case liveTickMsg:
		if m.paused {
			return m, liveTick()
		}
		m.elapsed = time.Since(m.start) - m.pausedFor
		if m.lastMemRead.IsZero() || time.Since(m.lastMemRead) >= liveMemRefreshInterval {
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			m.memMB = float64(stats.Alloc) / (1024 * 1024)
			m.lastMemRead = time.Now()
		}
		if m.done {
			return m, nil
		}
		return m, liveTick()
	case liveDoneMsg:
		if m.status != "Error" {
			m.status = "Completed"
			// In rewrite-heavy traces, "total" is only an input-line estimate and can
			// be much larger than the number of emitted monitor events. On completion,
			// show a consistent final progress state.
			if m.count > 0 {
				m.total = m.count
			}
		}
		m.done = true
		m.quitReady = true
		return m, nil
	case liveErrorMsg:
		m.status = "Error"
		if v.reason != "" && v.line != "" {
			m.errMsg = fmt.Sprintf("Line %s: %s", v.line, v.reason)
		} else if m.errMsg == "" && v.message != "" {
			m.errMsg = v.message
		}
		if v.event != "" {
			entry := fmt.Sprintf("%s %4s  %s", errorMarker(), v.line, v.event)
			index := 0
			if v.line != "" {
				if n, err := strconv.Atoi(v.line); err == nil {
					index = n
				}
			}
			m.addEntry(index, entry, entry)
		}
		m.errDetails = append(m.errDetails[:0], v.details...)
		if m.infoMsg == "" {
			m.infoMsg = ""
		}
		m.done = true
		m.quitReady = true
		return m, nil
	}

	return m, nil
}

func (m liveModel) View() string {
	// Render the dashboard UI into a boxed layout.
	width := m.width
	if width <= 0 {
		width = liveDefaultWidth
	}
	if width < liveMinWidth {
		width = liveMinWidth
	}
	inner := width - 2

	lines := []string{
		topLine(width),
		boxedLine("SpecMon Live Dashboard", inner),
		boxedLine(fmt.Sprintf("Model: %s | Status: %s", m.specPath, liveStatusLabel(m.status)), inner),
		midLine(width),
		boxedLine(m.progressLine(), inner),
		boxedLine(fmt.Sprintf("Processing Rate: %.1f events/s", m.rate()), inner),
		boxedLine(fmt.Sprintf("Configurations: %d", m.configs), inner),
		boxedLine(fmt.Sprintf("Memory Usage: %.1f MB", m.memMB), inner),
		boxedLine(fmt.Sprintf("Elapsed Time: %s", m.elapsed.Round(100*time.Millisecond)), inner),
		boxedLine(m.errorLine(), inner),
		boxedLine("", inner),
		boxedLine(m.lastHeader(), inner),
	}

	last := m.visibleEntries()
	if len(last) == 0 {
		lines = append(lines, boxedLine("  (none)", inner))
	} else {
		for _, ev := range last {
			text := ev.compact
			if m.verbose {
				text = ev.verbose
			}
			lines = append(lines, boxedLine("  "+text, inner))
		}
	}

	lines = append(lines, bottomLine(width))
	if m.jumpMode {
		lines = append(lines, fmt.Sprintf("Jump to event: %s (Enter to go, Esc to cancel)", m.jumpBuf))
	} else {
		lines = append(lines, "Press 'q' to quit, 'p' to pause, 'd' for details, 'v' for values, 'j' to jump, ↑/↓ to scroll")
		lines = append(lines, "Jump: press 'j', type event number, press Enter")
	}
	if m.infoMsg != "" {
		lines = append(lines, "Info: "+m.infoMsg)
	}
	if len(m.errDetails) > 0 {
		lines = append(lines, "")
		title := "✗ ERROR DETAILS:"
		if !color.NoColor {
			title = color.New(color.FgRed, color.Bold).Sprint(title)
		}
		lines = append(lines, title)
		lines = append(lines, m.errDetails...)
	}
	lines = m.applyViewport(lines)
	return strings.Join(lines, "\n")
}

func (m liveModel) applyViewport(lines []string) []string {
	height := m.height
	if height <= 0 {
		height = 24
	}
	if len(lines) <= height {
		return lines
	}
	maxOffset := len(lines) - height
	offset := m.viewOffset
	if offset < 0 {
		offset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}
	end := offset + height
	if end > len(lines) {
		end = len(lines)
	}
	return lines[offset:end]
}

func (m liveModel) errorLine() string {
	// Short error line for the dashboard.
	if m.errMsg == "" {
		return ""
	}
	return fmt.Sprintf("Last Error: %s", m.errMsg)
}

func (m liveModel) progressLine() string {
	// Progress bar line for the dashboard.
	if m.total <= 0 {
		return fmt.Sprintf("Events Processed: %d", m.count)
	}
	barWidth := liveProgressBarWidth
	percent := float64(m.count) / float64(m.total)
	if percent > 1 {
		percent = 1
	}
	filled := int(percent * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	return fmt.Sprintf("Events Processed: %d / %d  [%s] %d%%", m.count, m.total, bar, int(percent*100))
}

func (m liveModel) lastHeader() string {
	// Toggle between short and detailed history header.
	if m.details {
		return "Last 10 Events:"
	}
	return "Last 5 Events:"
}

func (m liveModel) eventAreaBounds() (int, int) {
	start := liveEventAreaStartLine
	visible := len(m.visibleEntries())
	if visible == 0 {
		visible = 1
	}
	end := start + visible - 1
	return start, end
}

func (m *liveModel) addEntry(index int, compact string, verbose string) {
	// Append an entry and enforce the history limit.
	m.entries = append(m.entries, liveEntry{index: index, compact: compact, verbose: verbose})
	if m.historyLimit > 0 && len(m.entries) > m.historyLimit {
		m.entries = m.entries[len(m.entries)-m.historyLimit:]
	}
	m.scrollOffset = 0
}

func (m liveModel) visibleEntries() []liveEntry {
	// Return the slice of entries currently visible in the UI.
	limit := m.pageSize()
	if len(m.entries) <= limit {
		return m.entries
	}
	start := len(m.entries) - limit - m.scrollOffset
	if start < 0 {
		start = 0
	}
	end := start + limit
	if end > len(m.entries) {
		end = len(m.entries)
	}
	return m.entries[start:end]
}

func (m liveModel) pageSize() int {
	// Page size depends on details mode.
	if m.details {
		return liveDetailedPageSize
	}
	return liveCompactPageSize
}

func (m liveModel) maxScrollOffset() int {
	// Max scroll offset given current history and page size.
	limit := m.pageSize()
	if len(m.entries) <= limit {
		return 0
	}
	return len(m.entries) - limit
}

func (m *liveModel) jumpTo() {
	// Jump to a specific event index in the history buffer.
	if m.jumpBuf == "" {
		m.jumpMode = false
		return
	}
	target, err := strconv.Atoi(m.jumpBuf)
	if err != nil {
		m.jumpMode = false
		m.jumpBuf = ""
		return
	}
	if len(m.entries) == 0 {
		m.infoMsg = "History is empty"
		m.jumpMode = false
		m.jumpBuf = ""
		return
	}
	oldest, newest := m.oldestNewest()
	pos := -1
	for i, entry := range m.entries {
		if entry.index == target {
			pos = i
			break
		}
	}
	switch {
	case pos >= 0:
		limit := m.pageSize()
		m.scrollOffset = max(0, len(m.entries)-limit-pos)
		m.infoMsg = ""
	case oldest > 0 && target < oldest:
		m.infoMsg = fmt.Sprintf("History limit: oldest event %d. Use --increase-history N", oldest)
	case newest > 0 && target > newest:
		m.infoMsg = fmt.Sprintf("History limit: newest event %d. Use --increase-history N", newest)
	default:
		m.infoMsg = "Event not in history buffer. Use --increase-history N"
	}
	m.jumpMode = false
	m.jumpBuf = ""
}

func (m liveModel) oldestNewest() (int, int) {
	// Find the oldest and newest event indices in history.
	oldest := 0
	newest := 0
	for _, entry := range m.entries {
		if entry.index <= 0 {
			continue
		}
		if oldest == 0 || entry.index < oldest {
			oldest = entry.index
		}
		if entry.index > newest {
			newest = entry.index
		}
	}
	return oldest, newest
}

func (m liveModel) rate() float64 {
	// Compute events per second.
	if m.elapsed <= 0 {
		return 0
	}
	return float64(m.count) / m.elapsed.Seconds()
}

func topLine(width int) string {
	// Box top border.
	if width < 2 {
		return ""
	}
	return "╔" + strings.Repeat("═", width-2) + "╗"
}

func midLine(width int) string {
	// Box middle border.
	if width < 2 {
		return ""
	}
	return "╠" + strings.Repeat("═", width-2) + "╣"
}

func bottomLine(width int) string {
	// Box bottom border.
	if width < 2 {
		return ""
	}
	return "╚" + strings.Repeat("═", width-2) + "╝"
}

func boxedLine(s string, inner int) string {
	// Clamp and pad a line inside the box.
	if inner <= 0 {
		return ""
	}
	clamped, visible := truncateANSIVisible(s, inner)
	pad := inner - visible
	if pad < 0 {
		pad = 0
	}
	return "║" + clamped + strings.Repeat(" ", pad) + "║"
}

func truncateANSIVisible(s string, maxVisible int) (string, int) {
	if maxVisible <= 0 {
		return "", 0
	}
	var b strings.Builder
	visible := 0
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) {
				c := s[j]
				if (c >= '0' && c <= '9') || c == ';' {
					j++
					continue
				}
				if c == 'm' {
					j++
				}
				break
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			size = 1
		}
		if visible >= maxVisible {
			break
		}
		b.WriteString(s[i : i+size])
		visible++
		i += size
	}
	if !strings.Contains(b.String(), "\x1b[0m") {
		b.WriteString("\x1b[0m")
	}
	return b.String(), visible
}

func liveTick() tea.Cmd {
	// Schedule a periodic tick for UI updates.
	return tea.Tick(liveTickInterval, func(t time.Time) tea.Msg {
		return liveTickMsg{t}
	})
}

func runLiveMonitor(
	r *MonitorConfig,
	m *monitor.Monitor,
	specPath string,
	eventSource io.ReadCloser,
	role string,
	decompose bool,
	defines []string,
	pid int,
) error {
	// Run the live dashboard and stream monitor events into it.
	start := time.Now()
	loader := startLoadingIndicator(true, "Preparing Live Dashboard...")
	total := estimateTotalEvents(r)
	historyLimit := r.LiveHistory
	if historyLimit <= 0 {
		historyLimit = liveDefaultHistory
	}
	var pauseFlag uint32
	program := tea.NewProgram(
		newLiveModel(specPath, start, len(m.Configs()), total, &pauseFlag, historyLimit),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	viewOpts := monitorViewOptions{
		showAllEvents:  r.ShowAll,
		showAllCfgs:    r.ShowAllCfgs,
		traceConfig:    r.TraceConfig,
		maxSuggestions: r.MaxSuggestions,
	}
	processErrs := make(chan *monitor.ProcessError, 1)

	go func() {
		defer close(processErrs)
		// Stream events to the dashboard, respecting rewrite and pre-trace modes.
		count := 0
		send := func(event term.Term) {
			count++
			compact := fmt.Sprintf("%s %4d  %s", successMarker(), count, formatCompactEvent(event))
			verbose := fmt.Sprintf("%s %4d  %s", successMarker(), count, formatVerboseEvent(event))
			program.Send(liveEventMsg{
				count:   count,
				compact: compact,
				verbose: verbose,
				configs: len(m.Configs()),
			})
		}

		if r.RewriteWith != "" {
			rewriteRules, _, _, err := ProcessRules(r.RewriteWith, role, decompose, defines)
			if err != nil {
				stopLoadingIndicator(loader)
				fmt.Fprintf(os.Stderr, "cannot process rewrite rules: %v\n", err)
				program.Send(liveDoneMsg{})
				return
			}

			if r.PreTrace != "" {
				preTrace, err := os.Open(r.PreTrace)
				if err != nil {
					stopLoadingIndicator(loader)
					fmt.Fprintf(os.Stderr, "cannot open pre-trace file: %v\n", err)
					program.Send(liveDoneMsg{})
					return
				}
				defer preTrace.Close()

				events := monitor.ParseEvents(preTrace, pid)
				_, consumedPre, preErrs := m.ProcessEvents(events, false, pid)
				consumeWithPause(consumedPre, &pauseFlag, send)
				if procErr := waitProcessError(preErrs); procErr != nil {
					details := m.BuildNoApplicableRuleDetails(procErr.Event, procErr.Line, viewOpts.showAllCfgs, viewOpts.traceConfig)
					program.Send(liveErrorMsg{
						message: fmt.Sprintf("Line %d: %s", details.Line, details.Reason),
						line:    strconv.Itoa(details.Line),
						event:   details.Event.String(),
						reason:  details.Reason,
						details: compactErrorDetails(formatNoApplicableRule(details, viewOpts.showAllEvents, viewOpts.maxSuggestions)),
					})
					processErrs <- procErr
					program.Send(liveDoneMsg{})
					return
				}
			}

			rewriter, err := monitor.NewMonitor(rewriteRules)
			if err != nil {
				stopLoadingIndicator(loader)
				fmt.Fprintf(os.Stderr, "cannot create rewrite monitor: %v\n", err)
				program.Send(liveDoneMsg{})
				return
			}
			rewriterEvents := monitor.ParseEvents(eventSource, pid)
			outs, _, rewriteErrs := rewriter.ProcessEvents(rewriterEvents, true, pid)
			_, consumedEvents, liveErrs := m.ProcessEvents(outs, false, pid)
			consumeWithPause(consumedEvents, &pauseFlag, send)
			if procErr := waitProcessError(rewriteErrs); procErr != nil {
				processErrs <- procErr
				program.Send(liveDoneMsg{})
				return
			}
			if procErr := waitProcessError(liveErrs); procErr != nil {
				details := m.BuildNoApplicableRuleDetails(procErr.Event, procErr.Line, viewOpts.showAllCfgs, viewOpts.traceConfig)
				program.Send(liveErrorMsg{
					message: fmt.Sprintf("Line %d: %s", details.Line, details.Reason),
					line:    strconv.Itoa(details.Line),
					event:   details.Event.String(),
					reason:  details.Reason,
					details: compactErrorDetails(formatNoApplicableRule(details, viewOpts.showAllEvents, viewOpts.maxSuggestions)),
				})
				processErrs <- procErr
				program.Send(liveDoneMsg{})
				return
			}
		} else {
			source := io.Reader(eventSource)
			if r.PreTrace != "" {
				preTrace, err := os.Open(r.PreTrace)
				if err != nil {
					stopLoadingIndicator(loader)
					fmt.Fprintf(os.Stderr, "cannot open pre-trace file: %v\n", err)
					program.Send(liveDoneMsg{})
					return
				}
				defer preTrace.Close()
				source = io.MultiReader(preTrace, eventSource)
			}

			events := monitor.ParseEvents(source, pid)
			_, consumed, errs := m.ProcessEvents(events, false, pid)
			consumeWithPause(consumed, &pauseFlag, send)
			if procErr := waitProcessError(errs); procErr != nil {
				details := m.BuildNoApplicableRuleDetails(procErr.Event, procErr.Line, viewOpts.showAllCfgs, viewOpts.traceConfig)
				program.Send(liveErrorMsg{
					message: fmt.Sprintf("Line %d: %s", details.Line, details.Reason),
					line:    strconv.Itoa(details.Line),
					event:   details.Event.String(),
					reason:  details.Reason,
					details: compactErrorDetails(formatNoApplicableRule(details, viewOpts.showAllEvents, viewOpts.maxSuggestions)),
				})
				processErrs <- procErr
				program.Send(liveDoneMsg{})
				return
			}
		}

		program.Send(liveDoneMsg{})
	}()

	stopLoadingIndicator(loader)
	_, runErr := program.Run()
	if runErr != nil {
		return runErr
	}
	if procErr := waitProcessError(processErrs); procErr != nil {
		return procErr.Err
	}
	return nil
}

func consumeWithPause(ch <-chan term.Term, pauseFlag *uint32, send func(term.Term)) {
	// Pause event consumption when the dashboard requests it.
	for {
		if atomic.LoadUint32(pauseFlag) == 1 {
			time.Sleep(livePausePollInterval)
			continue
		}
		event, ok := <-ch
		if !ok {
			return
		}
		send(event)
	}
}

func estimateTotalEvents(r *MonitorConfig) int {
	// Estimate total events for the dashboard progress bar.
	total := 0
	if r.PreTrace != "" && isFileInput(r.PreTrace) {
		if n, err := countParsedEvents(r.PreTrace); err == nil {
			total += n
		}
	}
	if r.In != "" && isFileInput(r.In) {
		if n, err := countLines(r.In); err == nil {
			total += n
		}
	}
	return total
}

func countParsedEvents(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	for range monitor.ParseEvents(f, -1) {
		n++
	}
	return n, nil
}

func errorMarker() string {
	if color.NoColor {
		return "✗"
	}
	return color.New(color.FgRed).Sprint("✗")
}

func liveStatusLabel(status string) string {
	switch status {
	case "Error":
		label := "✗ Error"
		if color.NoColor {
			return label
		}
		return color.New(color.FgRed, color.Bold).Sprint(label)
	case "Completed":
		label := "✓ Completed"
		if color.NoColor {
			return label
		}
		return color.New(color.FgGreen, color.Bold).Sprint(label)
	default:
		return status
	}
}

func compactErrorDetails(details string) []string {
	trimmed := strings.TrimRight(details, "\n")
	if trimmed == "" {
		return nil
	}
	// Keep the full structured monitor diagnostics (including expected events/config sections)
	// so live mode mirrors normal monitor error detail depth.
	return strings.Split(trimmed, "\n")
}
