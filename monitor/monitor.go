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

var (
	ErrNoApplicableRule    = errors.New("no applicable rule found")
	ErrRestrictionViolated = errors.New("restriction violated")
)

type Unifier[T any] interface {
	fmt.Stringer

	Unify(other T) (*term.Binding, error)
	Subst(b *term.Binding) T
}

// ruleKey identifies the predicate-name + arity an event term carries.
// Splitting trigger and hint rule dispatch by (name, arity) lets us skip
// the HasTriggers/HasHints filter in the hot loop and avoids visiting
// rules that pattern-match the same name with a different arity.
type ruleKey struct {
	name  string
	arity int
}

// Monitor is a monitor that processes events according to a set of rules.
type Monitor struct {
	// triggerRules maps event (name, arity) to rules whose triggers
	// contain a term with that signature. Pre-filtered so hot-loop
	// callers don't repeat HasTriggers().
	triggerRules map[ruleKey][]*rule.Rule

	// hintRules maps event (name, arity) to rules whose hints contain a
	// term with that signature. Pre-filtered so hot-loop callers don't
	// repeat HasHints().
	hintRules map[ruleKey][]*rule.Rule

	// epsilonRules are rules without triggers or hints, applied
	// directly to the configuration.
	epsilonRules []*rule.Rule

	// requirements maps each rule to the per-predicate name -> count its
	// LHS demands. The rule-applicability gate consults this to short-
	// circuit conflictSetFacts when a config can't possibly satisfy the
	// rule's LHS.
	requirements map[*rule.Rule]map[string]int

	// configs is the set of configurations that the monitor has.
	//
	// Dedup semantics: data.HashSet keys solely by Config.Hash() with
	// no Equal fallback (data/hashmap.go), so two configurations that
	// happen to collide on Hash() will silently merge here. The
	// monitor relies on Config.Hash being multiplicity-preserving
	// (sum-based with splitmix64 mixing, see configuration.go) so
	// trivially-distinct configurations (e.g. differing only in fact
	// multiplicity) cannot collide by construction. For all measured
	// workloads (signal-large, wireguard) the empirical genuine-
	// collision rate is zero.
	//
	// This is a workload-level guarantee, not a structural one. A
	// container adding Config.Equal-based collision safety on top of
	// hash bucketing was evaluated, but the resulting 30-100%
	// wall-time regression on signal-large was unacceptable for a
	// property that never fired on the measured workloads. If either
	// (a) a future workload exhibits hash collisions or (b) future
	// infrastructure (term interning, fact pools) reduces the
	// per-Equal cost to neutral, revisit an Equal-checking container.
	configs *data.HashSet[*Config]

	// stats includes the statistics of the monitor.
	stats *Stats
}

// computeRequirements returns the per-predicate-name count of facts the
// rule's LHS demands. A rule whose LHS asks for two instances of
// State() and one of Out() has needCount{"State": 2, "Out": 1}.
func computeRequirements(lhs []*rule.Fact) map[string]int {
	if len(lhs) == 0 {
		return nil
	}
	needCount := make(map[string]int, len(lhs))
	for _, f := range lhs {
		if f == nil {
			continue
		}
		needCount[f.Name]++
	}
	return needCount
}

// canMatchLHS reports whether c could possibly satisfy r's LHS. False
// means the conflictSetFacts call for (c, r) can be skipped entirely.
// True is necessary but not sufficient: the binding/unification work
// happens later.
func canMatchLHS(c *Config, needCount map[string]int) bool {
	if len(needCount) == 0 {
		return true
	}
	for name, need := range needCount {
		if c.CountByName(name) < need {
			return false
		}
	}
	return true
}

func NewMonitor(rules []*rule.Rule) (*Monitor, error) {
	if err := checkWellformedness(rules); err != nil {
		return nil, err
	}

	triggerRules := make(map[ruleKey][]*rule.Rule)
	hintRules := make(map[ruleKey][]*rule.Rule)
	var epsilonRules []*rule.Rule
	requirements := make(map[*rule.Rule]map[string]int, len(rules))

	for _, r := range rules {
		requirements[r] = computeRequirements(r.LHS)

		hasTriggers := r.HasTriggers()
		hasHints := r.HasHints()

		if !hasTriggers && !hasHints {
			epsilonRules = append(epsilonRules, r)
			continue
		}

		// A rule may carry several triggers (or hints) with the same
		// (name, arity) signature. Register it once per key: a single
		// handleTriggers/handleHints invocation already considers every
		// trigger/hint term of the rule, so a duplicate registration
		// would repeat the identical applications and emit their
		// actions twice.
		if hasTriggers {
			seenKeys := make(map[ruleKey]struct{}, len(r.Triggers()))
			for _, t := range r.Triggers() {
				k := ruleKeyForTerm(t)
				if _, ok := seenKeys[k]; ok {
					continue
				}
				seenKeys[k] = struct{}{}
				triggerRules[k] = append(triggerRules[k], r)
			}
		}
		if hasHints {
			seenKeys := make(map[ruleKey]struct{}, len(r.Hints()))
			for _, t := range r.Hints() {
				k := ruleKeyForTerm(t)
				if _, ok := seenKeys[k]; ok {
					continue
				}
				seenKeys[k] = struct{}{}
				hintRules[k] = append(hintRules[k], r)
			}
		}
	}

	return &Monitor{
		triggerRules: triggerRules,
		hintRules:    hintRules,
		epsilonRules: epsilonRules,
		requirements: requirements,
		configs:      data.NewHashSet(NewConfig()),
		stats:        &Stats{},
	}, nil
}

// Configs returns the configurations of the monitor.
func (m *Monitor) Configs() []*Config {
	return m.configs.Values()
}

// Stats returns the stats of the monitor.
func (m *Monitor) Stats() *Stats {
	return m.stats
}

// RuleApplication records one rule firing during a ProcessEvent call:
// the rule that ran, the binding that produced it, the resulting
// configuration, and the action facts emitted (forwarded to the
// rewrite output when the monitor runs in rewrite mode).
//
// RuleApplication has no Hash or Equal by design: applications are
// collected as plain slices, and deduplication happens only at the
// *Config boundary (HashSet[*Config]), where structural identity is
// well defined. Deduplicating applications themselves would have to
// fold every observable field (rule, binding, config, action list)
// into a 64-bit hash with no collision fallback.
type RuleApplication struct {
	rule    *rule.Rule
	binding *term.Binding
	config  *Config
	actions []*rule.Fact
}

// ProcessEvent consumes an event and performs the necessary monitoring actions.
// It returns the action facts produced by each successful rule application
// (one slice per RuleApplication) and an error if processing failed.
func (m *Monitor) ProcessEvent(a term.Term) ([][]*rule.Fact, error) {
	log.Debugf("ProcessEvent(%s)\n", a)

	updated := data.NewHashSet[*Config]()
	var actions [][]*rule.Fact

	aKey := ruleKeyForTerm(a)

	for _, c := range m.configs.Values() {
		var appliedTriggers []RuleApplication

		for _, r := range m.triggerRules[aKey] {
			next, err := m.handleTriggers(c, a, r)
			if err != nil {
				return nil, err
			}

			appliedTriggers = append(appliedTriggers, next...)
		}

		var appliedHints []RuleApplication

		for _, r := range m.hintRules[aKey] {
			next, err := m.handleHints(c, a, r)
			if err != nil {
				return nil, err
			}

			if len(appliedTriggers) == 0 {
				appliedHints = append(appliedHints, next...)

				continue
			}

			// Replicate the original HashSet-based filter as a slice
			// append with semantically-equivalent dedup.
			//
			// Original semantics: for each (t, h) pair add h iff
			// NOT(r is a start-rule of t.rule AND t.binding == h.binding).
			// With HashSet, repeated Adds of the same h collapsed; a
			// single h was kept iff AT LEAST ONE t in appliedTriggers
			// passed the predicate.
			//
			// Equivalently: h is suppressed iff FOR ALL t,
			//   IsStartRuleOf(r, t.rule) AND t.binding.Equal(h.binding).
			// We keep h otherwise. Each surviving h is appended once.
			for _, h := range next {
				suppress := true
				for _, t := range appliedTriggers {
					if !rule.IsStartRuleOf(r, t.rule) || !t.binding.Equal(h.binding) {
						suppress = false
						break
					}
				}
				if !suppress {
					appliedHints = append(appliedHints, h)
				}
			}
		}

		// Concatenated walk over the per-event applications. updated.Add
		// dedups *Config structurally; actions are forwarded in order
		// as the rewrite consumer expects.
		for _, t := range appliedTriggers {
			updated.Add(t.config)
			if len(t.actions) > 0 {
				actions = append(actions, t.actions)
			}
		}
		for _, t := range appliedHints {
			updated.Add(t.config)
			if len(t.actions) > 0 {
				actions = append(actions, t.actions)
			}
		}
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

		return nil, ErrNoApplicableRule
	}

	m.configs = updated

	return actions, nil
}

// findPossibleEvents returns the events that are possible in each configuration.
func (m *Monitor) findPossibleEvents() [][]term.Term {
	events := make([][]term.Term, m.configs.Size())

	// Collect each rule once across the three buckets (a rule may live in
	// multiple keys of triggerRules / hintRules).
	seen := make(map[*rule.Rule]struct{})
	var allRules []*rule.Rule
	for _, rs := range m.triggerRules {
		for _, r := range rs {
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			allRules = append(allRules, r)
		}
	}
	for _, rs := range m.hintRules {
		for _, r := range rs {
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			allRules = append(allRules, r)
		}
	}
	for _, r := range m.epsilonRules {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		allRules = append(allRules, r)
	}

	for i, c := range m.configs.Values() {
		var e []term.Term
		for _, r := range allRules {
			for _, b := range conflictSetFactsForConfig(c, r.LHS).Values() {
				s := r.Subst(b)
				e = append(e, s.Hints()...)
				e = append(e, s.Triggers()...)
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

func (m *Monitor) handleTriggers(c *Config, a term.Term, r *rule.Rule) ([]RuleApplication, error) {
	log.Tracef("handleTriggers(%s, %s, %s)\n\n", c, a, r.Name)

	if !canMatchLHS(c, m.requirements[r]) {
		return nil, nil
	}
	var C []RuleApplication

	rawTriggers := r.Triggers()

	// Try to extract a trigger binding from the event first. When this
	// succeeds, shared variables narrow the LHS fact search from O(N)
	// to O(1). Falls back to the original O(N) approach when the raw
	// trigger contains format expressions with functions of unbound
	// variables that cannot be evaluated without LHS-derived bindings.
	triggerBinding, triggerErr := getUniqueBinding(rawTriggers, a)

	var lhsPatterns []*rule.Fact
	if triggerErr == nil {
		lhsPatterns = make([]*rule.Fact, len(r.LHS))
		for i, f := range r.LHS {
			lhsPatterns[i] = f.Subst(triggerBinding)
		}
	} else {
		lhsPatterns = r.LHS
	}

	for _, b := range conflictSetFactsForConfig(c, lhsPatterns).Values() {
		var bt *term.Binding
		if triggerErr == nil {
			bt = triggerBinding.Extend(b)
		} else {
			// Fallback: match trigger instantiated with LHS binding.
			instTriggers := term.Terms(rawTriggers).Subst(b)
			u, err := getUniqueBinding(instTriggers, a)
			if err != nil {
				continue
			}
			bt = b.Extend(u)
		}

		instTriggers := term.Terms(rawTriggers).Subst(bt)

		d := c.Clone()
		d.AddSeen(a.Subst(bt))

		triggerBindings := conflictSetTerms(d.seen, instTriggers)

		if triggerBindings.Empty() {
			log.Infof("rule %s is not applicable: missing triggers", r.Name)
			C = append(C, RuleApplication{rule: r, binding: bt, config: d, actions: nil})

			continue
		}

		for _, tb := range triggerBindings.Values() {
			withTrigger := bt.Extend(tb)

			if d2, acts, err := d.ApplyRule(r, withTrigger); err == nil {
				log.Infof("rule %s is applicable\n  binding: %s", r.Name, withTrigger)

				// Check for applicable epsilon rules.
				// At most one may exist. Epsilon actions (if any) are
				// concatenated onto the trigger's so PPEvent rewrites
				// emitted by epsilon rules reach the rewrite output.
				e, epsActs, err := m.handleEpsilon(d2)
				if err != nil {
					return nil, err
				}

				C = append(C, RuleApplication{rule: r, binding: withTrigger, config: e, actions: concatActions(acts, epsActs)})
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

func (m *Monitor) handleHints(c *Config, a term.Term, r *rule.Rule) ([]RuleApplication, error) {
	log.Tracef("handleHints(%s, %s, %s)\n\n", c, a, r.Name)

	if !canMatchLHS(c, m.requirements[r]) {
		return nil, nil
	}
	var C []RuleApplication

	rawHints := r.Hints()

	// Mirror handleTriggers: extract hint binding from the event first
	// to narrow the LHS fact search; fall back to the original O(N)
	// approach when hint evaluation requires LHS-derived bindings.
	hintBinding, hintErr := getUniqueBinding(rawHints, a)

	var lhsPatterns []*rule.Fact
	if hintErr == nil {
		lhsPatterns = make([]*rule.Fact, len(r.LHS))
		for i, f := range r.LHS {
			lhsPatterns[i] = f.Subst(hintBinding)
		}
	} else {
		lhsPatterns = r.LHS
	}

	for _, b := range conflictSetFactsForConfig(c, lhsPatterns).Values() {
		var hb *term.Binding
		if hintErr == nil {
			hb = hintBinding.Extend(b)
		} else {
			instHints := term.Terms(rawHints).Subst(b)
			u, err := getUniqueBinding(instHints, a)
			if err != nil {
				continue
			}
			hb = b.Extend(u)
		}

		log.Infof("hint rule %s is applicable\n  binding: %s", r.Name, hb)

		d, hintActs, err := c.ApplyRule(r, hb)
		if err != nil {
			if errors.Is(err, ErrRestrictionViolated) {
				log.Infof("hint rule %s not applicable due to restriction: %v", r.Name, err)
				continue
			}
			return nil, err
		}

		// After applying the hint rule, we have to consume the event again with a trigger rule.
		g := a.Subst(hb)
		gKey := ruleKeyForTerm(g)

		var D []RuleApplication
		for _, rr := range m.triggerRules[gKey] {
			next, err := m.handleTriggers(d, g, rr)
			if err != nil {
				return nil, err
			}
			D = append(D, next...)
		}

		if len(D) == 0 {
			return nil, fmt.Errorf("no applicable rule found after accepting hint %s", g)
		}

		for _, t := range D {
			// Concatenate hint actions and downstream trigger actions.
			// concatActions allocates only when both sides are non-empty,
			// so the common single-source case stays alloc-free and we
			// avoid aliasing hintActs across iterations.
			C = append(C, RuleApplication{rule: r, binding: hb, config: t.config, actions: concatActions(hintActs, t.actions)})
		}
	}

	return C, nil
}

// handleEpsilon handles rules without triggers or hints. At most one
// epsilon rule may apply; if more than one matches the result is an
// error.
//
// Returns (resultConfig, epsilonActions, error). epsilonActions are the
// Act facts produced by the epsilon rule application, or nil when no
// epsilon rule fires. Callers must concatenate these onto the actions
// they collected from the preceding trigger/hint application so that
// PPEvent rewrites emitted by epsilon rules are forwarded to the
// rewrite output channel.
func (m *Monitor) handleEpsilon(c *Config) (*Config, []*rule.Fact, error) {
	log.Infof("\n\nhandleEpsilon()\n")

	// Track every applied (config, actions) pair so the "exactly one"
	// invariant is enforced at the end. In the success case there is at
	// most one entry; the slice avoids special-casing for early-exit.
	var configs []*Config
	var actions [][]*rule.Fact

	for _, r := range m.epsilonRules {
		if !canMatchLHS(c, m.requirements[r]) {
			continue
		}
		for _, b := range conflictSetFactsForConfig(c, r.LHS).Values() {
			log.Infof("epsilon rule %s is applicable\n  binding: %s", r.Name, b)

			d, acts, err := c.ApplyRule(r, b)
			if err != nil {
				return nil, nil, err
			}

			configs = append(configs, d)
			actions = append(actions, acts)
		}
	}

	if len(configs) > 1 {
		return nil, nil, errors.New("multiple applicable epsilon rules found")
	}

	// If no epsilon rule is applicable, return the original config and
	// no actions.
	if len(configs) == 0 {
		return c, nil, nil
	}

	return configs[0], actions[0], nil
}

// concatActions returns the concatenation of a and b without aliasing
// a's backing array. Returns the non-nil slice unchanged when the
// other is empty so the common single-source case does not allocate.
func concatActions(a, b []*rule.Fact) []*rule.Fact {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 {
		return b
	}
	out := make([]*rule.Fact, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
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

			actions, err := m.ProcessEvent(event.Event)
			if err != nil {
				log.Warnf("\nfinal configurations (%d)\n", m.configs.Size())
				for _, c := range m.configs.Values() {
					for _, f := range c.Facts() {
						log.Warnf("  %s\n", f.Name)
					}
				}

				if err := utils.KillProcess(pid); err != nil {
					log.Errorf("failed to kill process: %v", err)
				}
				log.Fatalf("error processing event: %v %s", err, event.Event)
			}

			m.stats.LatenciesProcessed = append(m.stats.LatenciesProcessed, time.Since(time.Unix(0, event.Time)))

			if rewrite {
				for _, group := range actions {
					for _, f := range group {
						if r := getRewriteTerm(f); r != nil {
							fr := term.Must(term.AsFunction(r))
							out <- &TimedEvent{Time: event.Time, Event: fr}
						}
					}
				}
			} else {
				consumed <- event.Event
			}
		}

		log.Warnf("\nfinal configurations (%d)\n", m.configs.Size())
		for _, c := range m.configs.Values() {
			for _, f := range c.Facts() {
				log.Warnf("  %s\n", f.Name)
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

// splitPairSignature returns the (name, arity) of the first component of
// a hint/trigger pair. Used to bucket rules into triggerRules / hintRules
// so dispatch is by (name, arity) rather than name only.
func splitPairSignature(t term.Term) (string, int) {
	fn, _ := splitPair(t)
	if fn == nil {
		log.Fatalf("unexpected hint or trigger: %s", t)
	}
	parsed := term.Must(term.AsFunction(fn))
	return parsed.Name, len(parsed.Args)
}

// ruleKeyForTerm returns the ruleKey of the first component of a
// hint/trigger pair.
func ruleKeyForTerm(t term.Term) ruleKey {
	name, arity := splitPairSignature(t)
	return ruleKey{name: name, arity: arity}
}
