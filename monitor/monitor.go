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

package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
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
	errCandidateEvaluation = errors.New("trigger or hint candidate evaluation failed")
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
				k, err := ruleKeyForTerm(t)
				if err != nil {
					return nil, fmt.Errorf("invalid trigger in rule %s: %w", r.Name, err)
				}
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
				k, err := ruleKeyForTerm(t)
				if err != nil {
					return nil, fmt.Errorf("invalid hint in rule %s: %w", r.Name, err)
				}
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
	var candidateEvaluationErr error

	aKey, err := ruleKeyForTerm(a)
	if err != nil {
		return nil, fmt.Errorf("invalid event: %w", err)
	}

	for _, c := range m.configs.Values() {
		var appliedTriggers []RuleApplication

		for _, r := range m.triggerRules[aKey] {
			next, err := m.handleTriggers(c, a, r)
			if err != nil {
				if errors.Is(err, errCandidateEvaluation) {
					if candidateEvaluationErr == nil {
						candidateEvaluationErr = err
					}
					continue
				}
				return nil, err
			}

			appliedTriggers = append(appliedTriggers, next...)
		}

		var appliedHints []RuleApplication

		for _, r := range m.hintRules[aKey] {
			next, err := m.handleHints(c, a, r)
			if err != nil {
				if errors.Is(err, errCandidateEvaluation) {
					if candidateEvaluationErr == nil {
						candidateEvaluationErr = err
					}
					continue
				}
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
		if candidateEvaluationErr != nil {
			return nil, candidateEvaluationErr
		}

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
	var evaluationErr error

	for _, t := range matches {
		u, err := target.Unify(t)
		log.Infof("    unifying %s with %s with %v\n", target, t, u)
		if err != nil {
			log.Infof("              no match: %v\n", err)
			log.Infof("              u: %v\n", u)
			if evaluationErr == nil && errors.Is(err, term.ErrEvaluation) {
				evaluationErr = err
			}

			continue
		}

		if unique != nil {
			return nil, fmt.Errorf("match with multiple bindings:\n  %s", unique)
		}

		log.Infof("              found unique binding: %s\n", u)
		unique = u
	}

	if unique == nil {
		if evaluationErr != nil {
			return nil, evaluationErr
		}
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
	var candidateEvaluationErr error
	if errors.Is(triggerErr, term.ErrEvaluation) {
		candidateEvaluationErr = triggerErr
	}

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
				if candidateEvaluationErr == nil && errors.Is(err, term.ErrEvaluation) {
					candidateEvaluationErr = err
				}
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

	if len(C) == 0 && candidateEvaluationErr != nil {
		return nil, fmt.Errorf("%w: %w", errCandidateEvaluation, candidateEvaluationErr)
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
	var candidateEvaluationErr error
	if errors.Is(hintErr, term.ErrEvaluation) {
		candidateEvaluationErr = hintErr
	}

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
				if candidateEvaluationErr == nil && errors.Is(err, term.ErrEvaluation) {
					candidateEvaluationErr = err
				}
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
		gKey, err := ruleKeyForTerm(g)
		if err != nil {
			return nil, fmt.Errorf("invalid event after accepting hint: %w", err)
		}

		var D []RuleApplication
		var downstreamCandidateErr error
		for _, rr := range m.triggerRules[gKey] {
			next, err := m.handleTriggers(d, g, rr)
			if err != nil {
				if errors.Is(err, errCandidateEvaluation) {
					if downstreamCandidateErr == nil {
						downstreamCandidateErr = err
					}
					continue
				}
				return nil, err
			}
			D = append(D, next...)
		}

		if len(D) == 0 {
			if downstreamCandidateErr != nil {
				return nil, downstreamCandidateErr
			}
			return nil, fmt.Errorf("%w after accepting hint %s", ErrNoApplicableRule, g)
		}

		for _, t := range D {
			// Concatenate hint actions and downstream trigger actions.
			// concatActions allocates only when both sides are non-empty,
			// so the common single-source case stays alloc-free and we
			// avoid aliasing hintActs across iterations.
			C = append(C, RuleApplication{rule: r, binding: hb, config: t.config, actions: concatActions(hintActs, t.actions)})
		}
	}

	if len(C) == 0 && candidateEvaluationErr != nil {
		return nil, fmt.Errorf("%w: %w", errCandidateEvaluation, candidateEvaluationErr)
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

const ViolationKindNoApplicableRule = "no_applicable_rule"

type ViolationInfo struct {
	Err        error
	ErrorKind  string
	TimedEvent *TimedEvent
	EventIndex int
	Stats      StatsSummary
}

type StreamResult struct {
	Violation *ViolationInfo
	Err       error
}

type StatsSummary struct {
	Received              int   `json:"received"`
	Processed             int   `json:"processed"`
	TotalTimeNS           int64 `json:"total_time"`
	AvgLatencyReceivedNS  int64 `json:"avg_latency_received"`
	AvgLatencyProcessedNS int64 `json:"avg_latency_processed"`
	AvgProcessingTimeNS   int64 `json:"avg_processing_time"`
	MedLatencyReceivedNS  int64 `json:"med_latency_received"`
	MedLatencyProcessedNS int64 `json:"med_latency_processed"`
}

type Stats struct {
	LatenciesReceived  []time.Duration
	LatenciesProcessed []time.Duration
	StartTime          time.Time
	EndTime            time.Time
}

func (s *Stats) String() string {
	summary := s.Summary(s.EndTime)

	return fmt.Sprintf("received: %d, processed: %d, total time: %s, avg latency received: %s, avg latency processed: %s, avg processing time: %s",
		summary.Received,
		summary.Processed,
		time.Duration(summary.TotalTimeNS),
		time.Duration(summary.AvgLatencyReceivedNS),
		time.Duration(summary.AvgLatencyProcessedNS),
		time.Duration(summary.AvgProcessingTimeNS))
}

func (s *Stats) Summary(end time.Time) StatsSummary {
	received := slices.Clone(s.LatenciesReceived)
	processed := slices.Clone(s.LatenciesProcessed)

	var summary StatsSummary
	summary.Received = len(received)
	summary.Processed = len(processed)
	if !s.StartTime.IsZero() && !end.IsZero() {
		summary.TotalTimeNS = end.Sub(s.StartTime).Nanoseconds()
	}

	paired := min(len(received), len(processed))
	var processingTotal time.Duration
	for i := 0; i < paired; i++ {
		processingTotal += processed[i] - received[i]
	}
	if paired > 0 {
		summary.AvgProcessingTimeNS = (processingTotal / time.Duration(paired)).Nanoseconds()
	}

	var receivedTotal time.Duration
	for _, latency := range received {
		receivedTotal += latency
	}
	if len(received) > 0 {
		summary.AvgLatencyReceivedNS = (receivedTotal / time.Duration(len(received))).Nanoseconds()
		summary.MedLatencyReceivedNS = time.Duration(utils.MedianDuration(received)).Nanoseconds()
	}

	var processedTotal time.Duration
	for _, latency := range processed {
		processedTotal += latency
	}
	if len(processed) > 0 {
		summary.AvgLatencyProcessedNS = (processedTotal / time.Duration(len(processed))).Nanoseconds()
		summary.MedLatencyProcessedNS = time.Duration(utils.MedianDuration(processed)).Nanoseconds()
	}

	return summary
}

func (s *Stats) JSON() string {
	jsonStats, _ := json.Marshal(s.Summary(s.EndTime))
	return string(jsonStats)
}

// ParseEvents converts an io.Reader containing JSON events into a channel of TimedEvent.
// It handles JSON parsing and filtering of comment lines.
func ParseEvents(ctx context.Context, r io.Reader) (<-chan *TimedEvent, <-chan error) {
	events := make(chan *TimedEvent, outChanSize)
	result := make(chan error, 1)
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 8*1024*1024)

	go func() {
		defer func() {
			close(events)
			close(result)
		}()

		for s.Scan() {
			if strings.HasPrefix(s.Text(), "//") {
				continue
			}

			event := &TimedEvent{}
			if err := json.Unmarshal(s.Bytes(), event); err != nil {
				result <- fmt.Errorf("parse event: %w", err)
				return
			}

			select {
			case events <- event:
			case <-ctx.Done():
				result <- ctx.Err()
				return
			}
		}

		if err := s.Err(); err != nil {
			result <- fmt.Errorf("scan events: %w", err)
			return
		}

		result <- nil
	}()

	return events, result
}

// EventStreams contains the asynchronous results of processing an event stream.
type EventStreams struct {
	Outputs  <-chan *TimedEvent
	Consumed <-chan term.Term
	Terminal <-chan StreamResult
}

// ProcessEvents processes events from a channel and returns its output streams.
// This is the core processing function that handles the monitoring logic.
func (m *Monitor) ProcessEvents(
	ctx context.Context,
	events <-chan *TimedEvent,
	rewrite bool,
) EventStreams {
	out := make(chan *TimedEvent, outChanSize)
	consumed := make(chan term.Term, consumedChanSize)
	terminal := make(chan StreamResult, 1)

	if m.stats.StartTime.IsZero() {
		m.stats.StartTime = time.Now()
	}

	go func() {
		result := StreamResult{}
		defer func() {
			m.stats.EndTime = time.Now()
			m.logFinalConfigs()
			close(out)
			close(consumed)
			terminal <- result
			close(terminal)
		}()

		for {
			var event *TimedEvent
			var ok bool
			select {
			case <-ctx.Done():
				result.Err = ctx.Err()
				return
			case event, ok = <-events:
				if !ok {
					return
				}
			}

			if event == nil || event.Event == nil {
				result.Err = errors.New("event or event term is nil")
				return
			}

			m.stats.LatenciesReceived = append(m.stats.LatenciesReceived, time.Since(time.Unix(0, event.Time)))

			actions, err := m.ProcessEvent(event.Event)
			if err != nil {
				if errors.Is(err, ErrNoApplicableRule) {
					end := time.Now()
					m.stats.EndTime = end
					result.Violation = &ViolationInfo{
						Err:        err,
						ErrorKind:  ViolationKindNoApplicableRule,
						TimedEvent: cloneTimedEvent(event),
						EventIndex: len(m.stats.LatenciesReceived),
						Stats:      m.stats.Summary(end),
					}
				} else {
					result.Err = fmt.Errorf("process event %s: %w", event.Event, err)
				}
				return
			}

			m.stats.LatenciesProcessed = append(m.stats.LatenciesProcessed, time.Since(time.Unix(0, event.Time)))

			if rewrite {
				for _, group := range actions {
					for _, f := range group {
						if r := getRewriteTerm(f); r != nil {
							fr, err := term.AsFunction(r)
							if err != nil {
								result.Err = fmt.Errorf("rewrite action %s: %w", f, err)
								return
							}
							select {
							case out <- &TimedEvent{Time: event.Time, Event: fr}:
							case <-ctx.Done():
								result.Err = ctx.Err()
								return
							}
						}
					}
				}
			} else {
				select {
				case consumed <- event.Event:
				case <-ctx.Done():
					result.Err = ctx.Err()
					return
				}
			}
		}
	}()

	return EventStreams{
		Outputs:  out,
		Consumed: consumed,
		Terminal: terminal,
	}
}

func (m *Monitor) logFinalConfigs() {
	log.Warnf("\nfinal configurations (%d)\n", m.configs.Size())
	for _, c := range m.configs.Values() {
		for _, f := range c.Facts() {
			log.Warnf("  %s\n", f.Name)
		}
	}
}

func cloneTimedEvent(event *TimedEvent) *TimedEvent {
	if event == nil {
		return nil
	}
	cloned, _ := cloneTerm(event.Event).(*term.Function)
	return &TimedEvent{Time: event.Time, Event: cloned}
}

func cloneTerm(t term.Term) term.Term {
	switch value := t.(type) {
	case nil:
		return nil
	case *term.Constant[int]:
		return term.NewConstant(value.Value)
	case *term.Constant[string]:
		return term.NewConstant(value.Value)
	case *term.Constant[[]byte]:
		return term.NewConstant(slices.Clone(value.Value))
	case *term.Variable:
		return term.NewVariable(value.Name)
	case *term.Function:
		args := make([]term.Term, len(value.Args))
		for i, arg := range value.Args {
			args[i] = cloneTerm(arg)
		}
		return term.NewFunction(value.Name, args)
	default:
		return nil
	}
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
func splitPairSignature(t term.Term) (string, int, error) {
	fn, _ := splitPair(t)
	if fn == nil {
		return "", 0, fmt.Errorf("expected event pair, got %s", t)
	}
	parsed, err := term.AsFunction(fn)
	if err != nil {
		return "", 0, fmt.Errorf("expected event function, got %s: %w", fn, err)
	}
	return parsed.Name, len(parsed.Args), nil
}

// ruleKeyForTerm returns the ruleKey of the first component of a
// hint/trigger pair.
func ruleKeyForTerm(t term.Term) (ruleKey, error) {
	name, arity, err := splitPairSignature(t)
	if err != nil {
		return ruleKey{}, err
	}
	return ruleKey{name: name, arity: arity}, nil
}
