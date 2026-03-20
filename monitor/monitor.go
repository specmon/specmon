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

package monitor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
	"github.com/specmon/specmon/utils"
)

const (
	// RewriteEventName denotes the event
	// that is used for outputting preprocessed events.
	//
	// A pre-process event should have exactly one argument
	// that is automatically unwrapped when outputted.
	RewriteEventName = "PPEvent"

	outChanSize      = 4096
	consumedChanSize = 4096
)

var (
	ErrNoApplicableRule    = errors.New("no applicable rule found")
	ErrRestrictionViolated = errors.New("restriction violated")
)

type Unifier[T any] interface {
	fmt.Stringer

	Unify(other T) (*term.Binding, error)
	Subst(b *term.Binding) T
}

// Monitor is a monitor that processes events according to a set of rules.
type Monitor struct {
	// rules is the set of rules that the monitor uses.
	// It is indexed by the rules' hints and triggers.
	rules map[string][]*rule.Rule

	// configs is the set of configurations that the monitor has.
	configs *data.HashSet[*Config]

	// stats includes the statistics of the monitor.
	stats *Stats

	// showAllEvents controls whether expected events are truncated in errors.
	showAllEvents bool

	// showAllConfigs controls whether all configs are listed on errors.
	showAllConfigs bool

	// traceConfig selects a specific config to display (1-based).
	traceConfig int

	// pauseFlag pauses processing when set to 1.
	pauseFlag *uint32

	// errorHandler receives structured no-applicable-rule diagnostics.
	errorHandler func(line int, event term.Term, details string)
}

func NewMonitor(rules []*rule.Rule) (*Monitor, error) {
	if err := checkWellformedness(rules); err != nil {
		return nil, err
	}

	rulesMap := make(map[string][]*rule.Rule)
	for _, r := range rules {
		if !r.HasHints() && !r.HasTriggers() {
			rulesMap[""] = append(rulesMap[""], r)

			continue
		}

		for _, t := range append(r.Hints(), r.Triggers()...) {
			rulesMap[splitPairFirstName(t)] = append(rulesMap[splitPairFirstName(t)], r)
		}
	}

	return &Monitor{
		rules:   rulesMap,
		configs: data.NewHashSet(NewConfig()),
		stats:   &Stats{},
	}, nil
}

// SetShowAllEvents toggles truncation for expected event listings.
func (m *Monitor) SetShowAllEvents(show bool) {
	// Toggle truncation for expected-event lists in error output.
	m.showAllEvents = show
}

// SetShowAllConfigs toggles whether all configurations are listed on errors.
func (m *Monitor) SetShowAllConfigs(show bool) {
	// Toggle whether all configurations are shown on errors.
	m.showAllConfigs = show
}

// SetTraceConfig selects a specific configuration to display (1-based).
func (m *Monitor) SetTraceConfig(n int) {
	// Select a specific configuration to display on errors (1-based).
	m.traceConfig = n
}

// SetPauseFlag sets a pause flag checked during event processing.
func (m *Monitor) SetPauseFlag(flag *uint32) {
	// Pause processing when the live dashboard requests it.
	m.pauseFlag = flag
}

// SetErrorHandler registers a callback for no-applicable-rule diagnostics.
func (m *Monitor) SetErrorHandler(handler func(line int, event term.Term, details string)) {
	m.errorHandler = handler
}

// Configs returns the configurations of the monitor.
func (m *Monitor) Configs() []*Config {
	return m.configs.Values()
}

// Stats returns the stats of the monitor.
func (m *Monitor) Stats() *Stats {
	return m.stats
}

type RuleApplication struct {
	rule    *rule.Rule
	binding *term.Binding
	config  *Config
}

// ProcessEvent consumes an event and performs the necessary monitoring actions.
// It returns an error if there was an issue while consuming the event.
func (m *Monitor) ProcessEvent(a term.Term) error {
	log.Debugf("ProcessEvent(%s)\n", a)

	updated := data.NewHashSet[*Config]()

	aName := splitPairFirstName(a)

	for _, c := range m.configs.Values() {
		appliedTriggers := data.NewHashSet[RuleApplication]()

		for _, r := range m.rules[aName] {
			if !r.HasTriggers() {
				continue
			}

			next, err := handleTriggers(c, a, r, m.rules)
			if err != nil {
				return err
			}

			appliedTriggers = appliedTriggers.Union(next)
		}

		appliedHints := data.NewHashSet[RuleApplication]()

		for _, r := range m.rules[aName] {
			if !r.HasHints() {
				continue
			}

			next, err := handleHints(c, a, r, m.rules)
			if err != nil {
				return err
			}

			if appliedTriggers.Empty() {
				appliedHints = appliedHints.Union(next)

				continue
			}

			appliedTriggers.Iterate(func(t RuleApplication) bool {
				next.Iterate(func(h RuleApplication) bool {
					// If r is not a start rule of an applicable trigger
					// or the binding of the hint rule is different from the trigger rule,
					// then add the configuration.
					if !rule.IsStartRuleOf(r, t.rule) || !t.binding.Equal(h.binding) {
						appliedHints.Add(h)
					}

					return true
				})

				return true
			})
		}

		appliedTriggers.Union(appliedHints).Iterate(func(t RuleApplication) bool {
			updated.Add(t.config)

			return true
		})
	}

	if updated.Size() > 1 {
		log.Infof("multiple configurations for event %.120s\n", a)
	}

	if updated.Empty() {
		return ErrNoApplicableRule
	}

	m.configs = updated

	return nil
}

// findPossibleEvents returns the events that are possible in each configuration.
func (m *Monitor) findPossibleEvents() [][]term.Term {
	events := make([][]term.Term, m.configs.Size())

	for i, c := range m.configs.Values() {
		var e []term.Term
		for _, rs := range m.rules {
			for _, r := range rs {
				for _, b := range conflictSetFacts(c.facts, r.LHS).Values() {
					s := r.Subst(b)
					e = append(e, s.Hints()...)
					e = append(e, s.Triggers()...)
				}
			}
		}

		events[i] = e
	}

	return events
}

// getUniqueBinding returns the bindings that match a term.
func getUniqueBinding(matches []term.Term, target term.Term) (*term.Binding, error) {
	log.Infof("     getUniqueBinding(%s, %s)\n", matches, target)

	var unique *term.Binding

	for _, t := range matches {
		u, err := target.Unify(t)
		log.Infof("    unifying %s with %s with %v\n", target, t, u)
		if err != nil {
			log.Infof("              no match: %v\n", err)
			log.Infof("              u: %v\n", u)

			continue
		}

		if unique != nil {
			return nil, fmt.Errorf("match with multiple bindings:\n  %s", unique)
		}

		log.Infof("              found unique binding: %s\n", u)
		unique = u
	}

	if unique == nil {
		return nil, errors.New("no unique and compatible binding found")
	}

	return unique, nil
}

func handleTriggers(c *Config, a term.Term, r *rule.Rule, rules map[string][]*rule.Rule) (*data.HashSet[RuleApplication], error) {
	log.Tracef("handleTriggers(%s, %s, %s)\n\n", c, a, r.Name)

	C := data.NewHashSet[RuleApplication]()
	for _, b := range conflictSetFacts(c.facts, r.LHS).Values() {
		// Instantiate the triggers with the found binding.
		// This ensures
		//   1. The binding found is compatible with b.
		//   2. The triggers can be evaluated and the functions they contain be evaluated.
		instTriggers := term.Terms(r.Triggers()).Subst(b)

		u, err := getUniqueBinding(instTriggers, a)
		if err != nil {
			continue
		}
		bt := b.Extend(u)

		d := c.Clone()
		d.AddSeen(a.Subst(bt))

		triggerBindings := conflictSetTerms(d.seen, instTriggers)

		if triggerBindings.Empty() {
			log.Infof("rule %s is not applicable: missing triggers", r.Name)
			C.Add(RuleApplication{r, bt, d})

			continue
		}

		for _, tb := range triggerBindings.Values() {
			withTrigger := bt.Extend(tb)

			if d, err := d.ApplyRule(r, withTrigger); err == nil {
				log.Infof("rule %s is applicable\n  binding: %s", r.Name, withTrigger)

				// Check for applicable epsilon rules.
				// At most one may exist.
				e, err := handleEpsilon(d, rules)
				if err != nil {
					return nil, err
				}

				C.Add(RuleApplication{r, withTrigger, e})
			} else if errors.Is(err, ErrRestrictionViolated) {
				log.Infof("rule %s not applicable due to restriction: %v", r.Name, err)
				continue
			} else {
				return nil, err
			}
		}
	}

	return C, nil
}

func handleHints(c *Config, a term.Term, r *rule.Rule, rules map[string][]*rule.Rule) (*data.HashSet[RuleApplication], error) {
	log.Tracef("handleHints(%s, %s, %s)\n\n", c, a, r.Name)

	aName := splitPairFirstName(a)

	C := data.NewHashSet[RuleApplication]()
	for _, b := range conflictSetFacts(c.facts, r.LHS).Values() {
		// Instantiate the hints with the found binding.
		// This ensures
		//   1. The binding found is compatible with b.
		//   2. The hints can be evaluated and the functions they contain be evaluated.
		instHints := term.Terms(r.Hints()).Subst(b)

		u, err := getUniqueBinding(instHints, a)
		if err != nil {
			continue
		}
		hb := b.Extend(u)

		log.Infof("hint rule %s is applicable\n  binding: %s", r.Name, hb)

		d, err := c.ApplyRule(r, hb)
		if err != nil {
			if errors.Is(err, ErrRestrictionViolated) {
				log.Infof("hint rule %s not applicable due to restriction: %v", r.Name, err)
				continue
			}
			return nil, err
		}

		// After applying the hint rule, we have to consume the event again with a trigger rule.
		g := a.Subst(hb)

		D := data.NewHashSet[RuleApplication]()
		for _, rr := range rules[aName] {
			// Skip rules without triggers - we only want to apply trigger rules here
			if !rr.HasTriggers() {
				continue
			}
			next, err := handleTriggers(d, g, rr, rules)
			if err != nil {
				return nil, err
			}
			D = D.Union(next)
		}

		if D.Size() == 0 {
			return nil, fmt.Errorf("no applicable rule found after accepting hint %s", g)
		}

		D.Iterate(func(t RuleApplication) bool {
			C.Add(RuleApplication{r, hb, t.config})

			return true
		})
	}

	return C, nil
}

// handleEpsilon handles rules without triggers or hints.
func handleEpsilon(c *Config, rules map[string][]*rule.Rule) (*Config, error) {
	log.Infof("\n\nhandleEpsilon()\n")
	var C []*Config

	for _, r := range rules[""] {
		for _, b := range conflictSetFacts(c.facts, r.LHS).Values() {
			log.Infof("epsilon rule %s is applicable\n  binding: %s", r.Name, b)

			d, err := c.ApplyRule(r, b)
			if err != nil {
				return nil, err
			}

			C = append(C, d)
		}
	}

	if len(C) > 1 {
		return nil, errors.New("multiple applicable epsilon rules found")
	}

	// If no epsilon rule is applicable, return the original config.
	if len(C) == 0 {
		return c, nil
	}

	return C[0], nil
}

func conflictSet[T Unifier[T]](items []T, body []T, indexable func(T) bool, name func(T) string, args func(T) []term.Term) *data.HashSet[*term.Binding] {
	log.Debugf("conflictSet( items=%d, body=%d )\n", len(items), len(body))

	// Index items by name, keeping track of original indices
	itemsByName := make(map[string][]int, len(items))
	for i, item := range items {
		if indexable(item) {
			itemsByName[name(item)] = append(itemsByName[name(item)], i)
		}
	}

	// Pre-filter candidates per body atom by constant positions for ordering.
	n := len(body)
	prefilter := make([][]int, n)
	order := make([]int, n)

	for i, p := range body {
		var candIndices []int
		if indexable(p) {
			candIndices = itemsByName[name(p)]
			if len(candIndices) == 0 {
				// No matches possible at all.
				return data.NewHashSet[*term.Binding]()
			}
			// Filter by constants in p (cheap check before unification).
			filtered := make([]int, 0, len(candIndices))
			for _, idx := range candIndices {
				f := items[idx]
				ok := true
				pArgs := args(p)
				fArgs := args(f)
				// This check assumes len(pArgs) == len(fArgs), which should hold for unification candidates.
				if len(pArgs) == len(fArgs) {
					for j, a := range pArgs {
						if a.GetType() == term.ConstantType {
							if !a.Equal(fArgs[j]) {
								ok = false
								break
							}
						}
					}
				} else {
					ok = false
				}

				if ok {
					filtered = append(filtered, idx)
				}
			}
			prefilter[i] = filtered
		} else {
			// Fallback: no indexing possible, scan all items.
			allIndices := make([]int, len(items))
			for j := range items {
				allIndices[j] = j
			}
			prefilter[i] = allIndices
		}
		order[i] = i
	}
	// Sort atoms by increasing number of prefiltered candidates to prune early.
	sort.Slice(order, func(i, j int) bool { return len(prefilter[order[i]]) < len(prefilter[order[j]]) })

	result := data.NewHashSet[*term.Binding]()

	// Track which items from the original items slice have been used.
	// This ensures multiset semantics s.t. each fact can only be consumed once.
	// Use backtracking (mark/unmark) instead of copying map on each recursive call.
	usedItems := make(map[int]bool)

	var dfs func(pos int, b *term.Binding)
	dfs = func(pos int, b *term.Binding) {
		if pos == n {
			result.Add(b)
			return
		}

		idx := order[pos]
		p := body[idx]
		// Apply current binding once per depth.
		ps := p.Subst(b)

		for _, itemIdx := range prefilter[idx] {
			// Skip if this fact has already been used in this binding path
			if usedItems[itemIdx] {
				continue
			}

			f := items[itemIdx]
			if delta, err := f.Unify(ps); err == nil {
				// Mark item as used (backtracking pattern)
				usedItems[itemIdx] = true
				dfs(pos+1, delta.Extend(b))
				// Unmark item for other branches
				delete(usedItems, itemIdx)
			}
		}
	}

	dfs(0, term.NewBinding())
	return result
}

// conflictSetFacts matches a sequence of fact patterns against a multiset of facts.
// It builds a per-predicate local index and uses DFS with early filtering by constants.
func conflictSetFacts(facts []*rule.Fact, body []*rule.Fact) *data.HashSet[*term.Binding] {
	return conflictSet(facts, body,
		func(_ *rule.Fact) bool { return true },
		func(f *rule.Fact) string { return f.Name },
		func(f *rule.Fact) []term.Term { return f.Args },
	)
}

// conflictSetTerms matches a sequence of term patterns against a set of seen terms.
// It builds a local index by function name and orders patterns by selectivity.
func conflictSetTerms(seen []term.Term, body []term.Term) *data.HashSet[*term.Binding] {
	return conflictSet(seen, body,
		func(t term.Term) bool {
			if fn, err := term.AsFunction(t); err == nil && fn != nil && fn.Name != term.PairFunctionName {
				return true
			}
			return false
		},
		func(t term.Term) string {
			if fn, err := term.AsFunction(t); err == nil && fn != nil {
				return fn.Name
			}
			return ""
		},
		func(t term.Term) []term.Term {
			if fn, err := term.AsFunction(t); err == nil && fn != nil {
				return fn.Args
			}
			return nil
		},
	)
}

//
// Helper functions
//

type TimedEvent struct {
	Time  int64          `json:"time"`
	Event *term.Function `json:"event"`
}

// ConsumedEvent represents a processed event and an acknowledgement hook.
type ConsumedEvent struct {
	Term term.Term
	Ack  chan struct{}
}

// Done acknowledges that the event line has been fully handled by the consumer.
func (e *ConsumedEvent) Done() {
	if e == nil || e.Ack == nil {
		return
	}
	close(e.Ack)
}

type Stats struct {
	LatenciesReceived  []time.Duration
	LatenciesProcessed []time.Duration
	StartTime          time.Time
	EndTime            time.Time
}

func (s *Stats) String() string {
	var avgLatencyReceived time.Duration
	for _, l := range s.LatenciesReceived {
		avgLatencyReceived += l
	}
	if len(s.LatenciesReceived) > 0 {
		avgLatencyReceived /= time.Duration(len(s.LatenciesReceived))
	}

	var avgLatencyProcessed time.Duration
	for _, l := range s.LatenciesProcessed {
		avgLatencyProcessed += l
	}
	if len(s.LatenciesProcessed) > 0 {
		avgLatencyProcessed /= time.Duration(len(s.LatenciesProcessed))
	}

	var avgProcessingTime time.Duration
	numEvents := min(len(s.LatenciesReceived), len(s.LatenciesProcessed))
	for i := 0; i < numEvents; i++ {
		avgProcessingTime += s.LatenciesProcessed[i] - s.LatenciesReceived[i]
	}
	if numEvents > 0 {
		avgProcessingTime /= time.Duration(numEvents)
	}

	var totalTime time.Duration
	if !s.StartTime.IsZero() && !s.EndTime.IsZero() && !s.EndTime.Before(s.StartTime) {
		totalTime = s.EndTime.Sub(s.StartTime)
	}

	return fmt.Sprintf("received: %d, processed: %d, total time: %s, avg latency received: %s, avg latency processed: %s, avg processing time: %s",
		len(s.LatenciesReceived), len(s.LatenciesProcessed), totalTime, avgLatencyReceived, avgLatencyProcessed, avgProcessingTime)
}

func (s *Stats) JSON() string {
	// If the monitor receives a SIGTEMR, the number of received and processed events may not match.
	// Hence, we only consider received events that have been processed.
	numEvents := min(len(s.LatenciesReceived), len(s.LatenciesProcessed))

	var avgLatencyReceived time.Duration
	var avgLatencyProcessed time.Duration
	var avgProcessingTime time.Duration

	for i := 0; i < numEvents; i++ {
		avgLatencyReceived += s.LatenciesReceived[i]
		avgLatencyProcessed += s.LatenciesProcessed[i]
		avgProcessingTime += s.LatenciesProcessed[i] - s.LatenciesReceived[i]
	}

	if numEvents > 0 {
		avgLatencyReceived /= time.Duration(numEvents)
		avgLatencyProcessed /= time.Duration(numEvents)
		avgProcessingTime /= time.Duration(numEvents)
	}

	var totalTime time.Duration
	if !s.StartTime.IsZero() && !s.EndTime.IsZero() && !s.EndTime.Before(s.StartTime) {
		totalTime = s.EndTime.Sub(s.StartTime)
	}

	stats := map[string]any{
		"received":              len(s.LatenciesReceived),
		"processed":             len(s.LatenciesProcessed),
		"total_time":            totalTime.Nanoseconds(),
		"avg_latency_received":  avgLatencyReceived.Nanoseconds(),
		"avg_latency_processed": avgLatencyProcessed.Nanoseconds(),
		"avg_processing_time":   avgProcessingTime.Nanoseconds(),
		"med_latency_received":  time.Duration(utils.MedianDuration(s.LatenciesReceived)).Nanoseconds(),
		"med_latency_processed": time.Duration(utils.MedianDuration(s.LatenciesProcessed)).Nanoseconds(),
	}

	jsonStats, err := json.Marshal(stats)
	if err != nil {
		panic(err)
	}

	return string(jsonStats)
}

// ParseEvents converts an io.Reader containing JSON events into a channel of TimedEvent.
// It handles JSON parsing and filtering of comment lines.
func ParseEvents(r io.Reader, pid int) <-chan *TimedEvent {
	events := make(chan *TimedEvent, outChanSize)
	s := bufio.NewScanner(r)

	go func() {
		defer close(events)

		for s.Scan() {
			if strings.HasPrefix(s.Text(), "//") {
				continue
			}

			event := &TimedEvent{}
			if err := json.Unmarshal(s.Bytes(), event); err != nil {
				if err := utils.KillProcess(pid); err != nil {
					log.Errorf("failed to kill process: %v", err)
				}
				log.Fatalf("failed to parse event: %v", err)
			}

			events <- event
		}

		if err := s.Err(); err != nil {
			if err := utils.KillProcess(pid); err != nil {
				log.Errorf("failed to kill process: %v", err)
			}
			log.Fatalf("scanner error: %v", err)
		}
	}()

	return events
}

// ProcessEvents processes events from a channel and returns output channels.
// This is the core processing function that handles the monitoring logic.
func (m *Monitor) ProcessEvents(events <-chan *TimedEvent, rewrite bool, pid int) (<-chan *TimedEvent, <-chan *ConsumedEvent) {
	out := make(chan *TimedEvent, outChanSize)
	consumed := make(chan *ConsumedEvent)

	m.stats.StartTime = time.Now()

	go func() {
		defer close(out)
		defer close(consumed)
		defer func() { m.stats.EndTime = time.Now() }()

		line := 0
		for event := range events {
			line++
			if event == nil || event.Event == nil {
				if err := utils.KillProcess(pid); err != nil {
					log.Errorf("failed to kill process: %v", err)
				}
				log.Fatalf("event is nil: %v", event)
			}

			for m.pauseFlag != nil && atomic.LoadUint32(m.pauseFlag) == 1 {
				time.Sleep(50 * time.Millisecond)
			}

			m.stats.LatenciesReceived = append(m.stats.LatenciesReceived, time.Since(time.Unix(0, event.Time)))

			if err := m.ProcessEvent(event.Event); err != nil {
				if errors.Is(err, ErrNoApplicableRule) {
					details := m.formatNoApplicableRule(event.Event, line)
					if m.errorHandler != nil {
						m.errorHandler(line, event.Event, details)
					} else {
						fmt.Fprintln(os.Stdout, formatErrorLineMarker(line, event.Event))
						fmt.Fprintln(os.Stdout)
						fmt.Fprintln(os.Stdout, details)
					}
				}
				log.Warnf("\nfinal configurations (%d)\n", m.configs.Size())
				for _, c := range m.configs.Values() {
					for _, f := range c.facts {
						log.Warnf("  %s\n", f.Name)
					}
				}

				if err := utils.KillProcess(pid); err != nil {
					log.Errorf("failed to kill process: %v", err)
				}
				return
			}

			m.stats.LatenciesProcessed = append(m.stats.LatenciesProcessed, time.Since(time.Unix(0, event.Time)))

			if rewrite {
				for _, c := range m.configs.Values() {
					select {
					case p := <-c.queue:
						for _, f := range p {
							if r := getRewriteTerm(f); r != nil {
								fr := term.Must(term.AsFunction(r))
								out <- &TimedEvent{Time: event.Time, Event: fr}
							}
						}
					default:
						// No output to process
					}
				}
			} else {
				ce := &ConsumedEvent{Term: event.Event, Ack: make(chan struct{})}
				consumed <- ce
				<-ce.Ack
			}
		}

		log.Warnf("\nfinal configurations (%d)\n", m.configs.Size())
		for _, c := range m.configs.Values() {
			for _, f := range c.facts {
				log.Warnf("  %s\n", f.Name)
			}
		}
	}()

	return out, consumed
}

func formatErrorLineMarker(line int, event term.Term) string {
	marker := "✗"
	if !color.NoColor {
		marker = color.New(color.FgRed).Sprint("✗")
	}
	return fmt.Sprintf("%s %4d  %s", marker, line, event)
}

func getRewriteTerm(f *rule.Fact) term.Term {
	if f.Name == RewriteEventName && len(f.Args) == 1 {
		return f.Args[0]
	}

	return nil
}

type possibleEvent struct {
	ruleName string
	term     term.Term
}

func (m *Monitor) findPossibleEventsWithRules() [][]possibleEvent {
	// Collect possible next events for each config, with the rule name that enables them.
	events := make([][]possibleEvent, m.configs.Size())

	for i, c := range m.configs.Values() {
		var e []possibleEvent
		for _, rs := range m.rules {
			for _, r := range rs {
				for _, b := range conflictSetFacts(c.facts, r.LHS).Values() {
					s := r.Subst(b)
					for _, h := range s.Hints() {
						e = append(e, possibleEvent{ruleName: r.Name, term: h})
					}
					for _, t := range s.Triggers() {
						e = append(e, possibleEvent{ruleName: r.Name, term: t})
					}
				}
			}
		}

		events[i] = e
	}

	return events
}

func (m *Monitor) formatNoApplicableRule(event term.Term, line int) string {
	// Build a structured error message with grouped expected events.
	var b strings.Builder
	headline := "✗ ERROR: Event Processing Failed"
	if !color.NoColor {
		headline = color.New(color.FgRed, color.Bold).Sprint(headline)
	}
	fmt.Fprintln(&b, headline)
	fmt.Fprintf(&b, "  Event: %s\n", event)
	if line > 0 {
		fmt.Fprintf(&b, "  Line: %d\n", line)
	}
	fmt.Fprintf(&b, "  Reason: No applicable rule found\n")
	fmt.Fprintln(&b)

	configCount := m.configs.Size()
	if configCount > 1 {
		fmt.Fprintf(&b, "WARNING: Multiple Configurations Detected (%d)\n", configCount)
		fmt.Fprintln(&b, "  The specification has branched into multiple possible states.")
		fmt.Fprintln(&b, "  Allowed events differ by configuration.")
	}

	possibleEvents := m.findPossibleEventsWithRules()
	showAll := m.showAllConfigs
	traceConfig := m.traceConfig
	if traceConfig > 0 && traceConfig > configCount {
		fmt.Fprintf(&b, "\nWARNING: Config #%d not found; showing all configs\n", traceConfig)
		showAll = true
		traceConfig = 0
	}

	for i, events := range possibleEvents {
		configNum := i + 1
		if configCount > 1 {
			if traceConfig > 0 && configNum != traceConfig {
				continue
			}
			if !showAll && traceConfig == 0 && configNum != 1 {
				continue
			}
			fmt.Fprintf(&b, "\nConfig #%d:\n", configNum)
		}
		formatPossibleEvents(&b, events, m.showAllEvents)
	}

	if configCount > 1 && !showAll && traceConfig == 0 {
		fmt.Fprintln(&b, "Use --trace-config=N to follow specific configuration")
		fmt.Fprintln(&b, "Use --show-all-configs to see all possible events per configuration")
	}

	return b.String()
}

func formatPossibleEvents(b *strings.Builder, events []possibleEvent, showAll bool) {
	// Group expected events by category/name and print a limited, readable list.
	const defaultMaxPerGroup = 10
	const defaultMaxOther = 5
	maxPerGroup := defaultMaxPerGroup
	maxOther := defaultMaxOther
	if showAll {
		maxPerGroup = len(events)
		maxOther = len(events)
	}

	groups := groupEvents(events)
	if len(groups) == 0 {
		fmt.Fprintln(b, "No expected events available.")
		return
	}
	order := []string{"send", "receive", "random"}
	labels := map[string]string{
		"send":    "Network Send",
		"receive": "Network Receive",
		"random":  "Fresh Random",
	}
	truncated := false

	hasPrimaryGroups := false
	for _, category := range order {
		if len(groups[category]) > 0 {
			hasPrimaryGroups = true
			break
		}
	}
	if hasPrimaryGroups {
		showCount := min(maxPerGroup, len(events))
		fmt.Fprintf(b, "Expected Events (showing %d of %d, grouped by event name):\n\n", showCount, len(events))
	}

	for _, category := range order {
		items := groups[category]
		if len(items) == 0 {
			continue
		}

		for _, g := range items {
			fmt.Fprintf(b, "%s/%d - %s:\n", g.name, g.arity, labels[category])
			limit := min(len(g.items), maxPerGroup)
			for i := 0; i < limit; i++ {
				fmt.Fprintf(b, "  [%s] %s\n", g.items[i].ruleName, g.items[i].term)
			}
			if len(g.items) > maxPerGroup {
				fmt.Fprintf(b, "  ... (%d more)\n", len(g.items)-maxPerGroup)
				truncated = true
			}
			fmt.Fprintln(b)
		}
	}

	otherItems := groups["other"]
	if len(otherItems) > 0 {
		var flat []possibleEvent
		for _, g := range otherItems {
			flat = append(flat, g.items...)
		}
		limit := min(len(flat), maxOther)
		fmt.Fprintf(b, "Other Events (%d total, showing %d):\n", len(flat), limit)
		for i := 0; i < limit; i++ {
			fmt.Fprintf(b, "  [%s] %s\n", flat[i].ruleName, flat[i].term)
		}
		if len(flat) > maxOther {
			truncated = true
		}
		fmt.Fprintln(b)
	}

	if truncated {
		fmt.Fprintf(b, "Use --show-all-events to see all %d possibilities\n", len(events))
		fmt.Fprintln(b, "Use --debug for full trace and rule details")
	}
}

type eventGroup struct {
	name  string
	arity int
	items []possibleEvent
}

func groupEvents(events []possibleEvent) map[string][]eventGroup {
	// Group events by category and name/arity for display.
	grouped := make(map[string]map[string]*eventGroup)

	for _, e := range events {
		name, arity, ok := eventNameArity(e.term)
		if !ok {
			name = "unknown"
			arity = 0
		}
		category := eventCategory(name)
		if grouped[category] == nil {
			grouped[category] = make(map[string]*eventGroup)
		}
		key := fmt.Sprintf("%s/%d", name, arity)
		if grouped[category][key] == nil {
			grouped[category][key] = &eventGroup{name: name, arity: arity}
		}
		grouped[category][key].items = append(grouped[category][key].items, e)
	}

	result := make(map[string][]eventGroup)
	for category, groups := range grouped {
		for _, g := range groups {
			result[category] = append(result[category], *g)
		}
		sort.Slice(result[category], func(i, j int) bool {
			if result[category][i].name == result[category][j].name {
				return result[category][i].arity < result[category][j].arity
			}
			return result[category][i].name < result[category][j].name
		})
	}

	return result
}

func eventNameArity(t term.Term) (string, int, bool) {
	// Extract event name and arity, unwrapping pair-wrapped calls.
	fn, err := term.AsFunction(t)
	if err != nil || fn == nil {
		return "", 0, false
	}
	if fn.Name == term.PairFunctionName && len(fn.Args) == 2 {
		call, err := term.AsFunction(fn.Args[0])
		if err == nil && call != nil {
			return call.Name, len(call.Args), true
		}
	}

	return fn.Name, len(fn.Args), true
}

func eventCategory(name string) string {
	// Map event names into semantic categories used in the error display.
	switch strings.ToLower(name) {
	case "send", "out", "sendmessage":
		return "send"
	case "recv", "receive", "in", "receivemessage":
		return "receive"
	case "random", "fr":
		return "random"
	default:
		return "other"
	}
}

// CheckWellformedness checks if the rules are well-formed.
func checkWellformedness(rules []*rule.Rule) error {
	for _, r := range rules {
		// A hint rule must have a non-empty LHS.
		if r.HasHints() && len(r.LHS) == 0 {
			return fmt.Errorf("hint rule %s has empty LHS", r.Name)
		}
	}

	return nil
}

func splitPairFirstName(t term.Term) string {
	fn, _ := splitPair(t)

	if fn == nil {
		log.Fatalf("unexpected hint or trigger: %s", t)
	}

	return term.Must(term.AsFunction(fn)).Name
}
