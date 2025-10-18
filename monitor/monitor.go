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
	"sort"
	"strings"
	"time"

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

var ErrNoApplicableRule = errors.New("no applicable rule found")

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

	// settings hold user configurations to alter monitor behavior
	settings map[string]interface{}
}

func NewMonitor(rules []*rule.Rule, settings map[string]interface{}) (*Monitor, error) {
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
		rules:    rulesMap,
		configs:  data.NewHashSet(NewConfig()),
		stats:    &Stats{},
		settings: settings,
	}, nil
}

// Settings returns the configurations of the monitor.
func (m *Monitor) Settings() map[string]interface{} {
	return m.settings
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
		possibleEvents := m.findPossibleEvents()
		for i, events := range possibleEvents {
			log.Errorf("allowed events in configuration %d:\n", i)
			for _, e := range events {
				log.Errorf("  %.120s\n", e)
			}
		}

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
			return nil, err
		}

		// After applying the hint rule, we have to consume the event again with a trigger rule.
		g := a.Subst(hb)

		D := data.NewHashSet[RuleApplication]()
		for _, rr := range rules[aName] {
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
	var dfs func(pos int, b *term.Binding, usedItems map[int]bool)
	dfs = func(pos int, b *term.Binding, usedItems map[int]bool) {
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
				// Create new used items map with this item marked as used
				newUsedItems := make(map[int]bool)
				for k, v := range usedItems {
					newUsedItems[k] = v
				}
				newUsedItems[itemIdx] = true
				dfs(pos+1, delta.Extend(b), newUsedItems)
			}
		}
	}

	dfs(0, term.NewBinding(), make(map[int]bool))
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
	for i := range s.LatenciesReceived {
		avgProcessingTime += s.LatenciesProcessed[i] - s.LatenciesReceived[i]
	}
	if len(s.LatenciesReceived) > 0 {
		avgProcessingTime /= time.Duration(len(s.LatenciesReceived))
	}

	totalTime := s.EndTime.Sub(s.StartTime)

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

	if len(s.LatenciesProcessed) > 0 {
		avgLatencyReceived /= time.Duration(numEvents)
		avgLatencyProcessed /= time.Duration(numEvents)
		avgProcessingTime /= time.Duration(numEvents)
	}

	totalTime := s.EndTime.Sub(s.StartTime)

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
func (m *Monitor) ProcessEvents(events <-chan *TimedEvent, rewrite bool, pid int) (<-chan *TimedEvent, <-chan term.Term) {
	out := make(chan *TimedEvent, outChanSize)
	consumed := make(chan term.Term, consumedChanSize)

	m.stats.StartTime = time.Now()

	go func() {
		defer close(out)
		defer close(consumed)
		defer func() { m.stats.EndTime = time.Now() }()

		for event := range events {
			if event == nil || event.Event == nil {
				if err := utils.KillProcess(pid); err != nil {
					log.Errorf("failed to kill process: %v", err)
				}
				log.Fatalf("event is nil: %v", event)
			}

			m.stats.LatenciesReceived = append(m.stats.LatenciesReceived, time.Since(time.Unix(0, event.Time)))

			if err := m.ProcessEvent(event.Event); err != nil {
				log.Warnf("\nfinal configurations (%d)\n", m.configs.Size())
				for _, c := range m.configs.Values() {
					for _, f := range c.facts {
						f.LogArgs(m.Settings())
					}
				}

				if err := utils.KillProcess(pid); err != nil {
					log.Errorf("failed to kill process: %v", err)
				}
				log.Fatalf("error processing event: %v %s", err, event.Event)
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
				consumed <- event.Event
			}
		}

		log.Warnf("\nfinal configurations (%d)\n", m.configs.Size())
		counter := 0
		for _, c := range m.configs.Values() {
			counter++
			log.Warnf("Configuration %d\n", counter)
			for _, f := range c.facts {
				f.LogArgs(m.Settings())
			}
		}
	}()

	return out, consumed
}

func getRewriteTerm(f *rule.Fact) term.Term {
	if f.Name == RewriteEventName && len(f.Args) == 1 {
		return f.Args[0]
	}

	return nil
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
