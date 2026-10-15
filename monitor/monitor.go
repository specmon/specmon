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
	outChanSize      = 4096
	consumedChanSize = 4096
)

var (
	ErrNoApplicableRule    = errors.New("no applicable rule found")
	ErrRestrictionViolated = errors.New("restriction violated")
	// ErrEpsilonDepth reports an epsilon candidate that is left after the
	// epsilon step of a transition.
	ErrEpsilonDepth = errors.New("epsilon rule applicable after an epsilon step")
	// ErrNondeterministicRewrite reports that the rule applications for one
	// event emit different event sequences, which a single output stream
	// cannot represent.
	ErrNondeterministicRewrite = errors.New("nondeterministic rewrite")
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

type triggerRuleEntry struct {
	ordinal      int
	rule         *rule.Rule
	lhsVariables []*term.Variable
}

// Monitor is a monitor that processes events according to a set of rules.
type Monitor struct {
	// triggerRules maps event (name, arity) to rules whose triggers
	// contain a term with that signature. Pre-filtered so hot-loop
	// callers don't repeat HasTriggers().
	triggerRules map[ruleKey][]triggerRuleEntry

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

	// rules preserves the input order used by pending applications.
	rules []*rule.Rule

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

	triggerRules := make(map[ruleKey][]triggerRuleEntry)
	hintRules := make(map[ruleKey][]*rule.Rule)
	var epsilonRules []*rule.Rule
	requirements := make(map[*rule.Rule]map[string]int, len(rules))

	for ordinal, r := range rules {
		requirements[r] = computeRequirements(r.LHS)

		hasTriggers := r.HasTriggers()
		hasHints := r.HasHints()

		if !hasTriggers && !hasHints {
			epsilonRules = append(epsilonRules, r)
			continue
		}

		// A rule may carry several triggers (or hints) with the same
		// (name, arity) signature. Register it once per key: one call of
		// startPending (for a rule with several triggers), handleTriggers
		// or handleHints already considers every trigger or hint term of
		// the rule with that key, so a duplicate registration would repeat
		// its applications and emit their actions twice.
		if hasTriggers {
			triggers := r.Triggers()
			var lhsVariables []*term.Variable
			if len(triggers) > 1 {
				lhsVariables = rule.Facts(r.LHS).Vars()
			}
			seenKeys := make(map[ruleKey]struct{}, len(triggers))
			for _, t := range triggers {
				k, err := ruleKeyForTerm(t)
				if err != nil {
					return nil, fmt.Errorf("invalid trigger in rule %s: %w", r.Name, err)
				}
				if _, ok := seenKeys[k]; ok {
					continue
				}
				seenKeys[k] = struct{}{}
				triggerRules[k] = append(triggerRules[k], triggerRuleEntry{
					ordinal:      ordinal,
					rule:         r,
					lhsVariables: lhsVariables,
				})
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
		rules:        slices.Clone(rules),
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
	applications, err := m.processEvent(a)
	if err != nil {
		return nil, err
	}

	var actions [][]*rule.Fact
	for _, application := range applications {
		if len(application.actions) > 0 {
			actions = append(actions, application.actions)
		}
	}
	return actions, nil
}

// processEvent consumes an event from every configuration and returns all
// rule applications, including those without actions.
func (m *Monitor) processEvent(a term.Term) ([]RuleApplication, error) {
	log.Debugf("ProcessEvent(%s)\n", a)

	updated := data.NewHashSet[*Config]()
	var applied []RuleApplication

	aKey, err := ruleKeyForTerm(a)
	if err != nil {
		return nil, fmt.Errorf("invalid event: %w", err)
	}

	for _, c := range m.configs.Values() {
		applications, err := m.processConfigEvent(c, a, aKey)
		if err != nil {
			return nil, err
		}

		for _, t := range applications {
			updated.Add(t.config)
		}
		applied = append(applied, applications...)
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

	return applied, nil
}

// processConfigEvent returns every transition that consumes event from c.
// It does not mutate m.configs, which keeps a rewrite configuration paired
// with only the downstream configurations reached through that rewrite path.
func (m *Monitor) processConfigEvent(c *Config, event term.Term, key ruleKey) ([]RuleApplication, error) {
	appliedTriggers, _, err := m.handleTriggerPaths(c, event, key, false)
	if err != nil {
		return nil, err
	}

	var appliedHints []RuleApplication
	for _, r := range m.hintRules[key] {
		next, err := m.handleHints(c, event, r)
		if err != nil {
			return nil, err
		}

		for _, hinted := range next {
			// One valid direct continuation from the same family with an
			// equal binding is enough to suppress the hinted start.
			suppress := false
			for _, direct := range appliedTriggers {
				if rule.IsStartRuleOf(r, direct.rule) && direct.binding.Equal(hinted.binding) {
					suppress = true
					break
				}
			}
			if !suppress {
				appliedHints = append(appliedHints, hinted)
			}
		}
	}

	applications := slices.Concat(appliedTriggers, appliedHints)
	return applications, nil
}

// findPossibleEvents returns the events that are possible in each configuration.
func (m *Monitor) findPossibleEvents() [][]term.Term {
	events := make([][]term.Term, m.configs.Size())

	for i, c := range m.configs.Values() {
		var e []term.Term
		for _, r := range m.rules {
			for _, b := range conflictSetFactsForConfig(c, r.LHS).Values() {
				for _, hint := range r.Hints() {
					e = append(e, hint.Subst(b))
				}
				for _, trigger := range r.Triggers() {
					e = append(e, trigger.Subst(b))
				}
			}
		}
		for _, pending := range c.pending {
			r := m.rules[pending.ruleOrdinal]
			triggers := r.Triggers()
			for _, slot := range pending.outstanding {
				e = append(e, triggers[slot].Subst(pending.binding))
			}
		}

		events[i] = e
	}

	return events
}

// getUniqueBinding returns the binding under which target unifies with
// the hint terms in matches. Equal bindings of several hint terms count
// once. Distinct bindings are an error, so the hint candidate is skipped.
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
			if unique.Equal(u) {
				continue
			}
			return nil, fmt.Errorf("match with multiple bindings:\n  %s\n  %s", unique, u)
		}

		log.Infof("              found unique binding: %s\n", u)
		unique = u
	}

	if unique == nil {
		return nil, errors.New("no unique and compatible binding found")
	}

	return unique, nil
}

// handleTriggerPaths returns the applications of the trigger rules and
// pending applications that consume event in c. A hint continuation uses
// only rules with a single trigger: it neither starts nor advances a
// pending application of a rule with several triggers. applied reports
// whether a triggered rule was applied, even if the epsilon step that
// follows then ended every branch, so that no application remains.
func (m *Monitor) handleTriggerPaths(c *Config, event term.Term, key ruleKey, hintContinuation bool) ([]RuleApplication, bool, error) {
	var applications []RuleApplication
	var anchored map[int]bool
	var applied bool
	if !hintContinuation {
		var err error
		applications, anchored, applied, err = m.advancePending(c, event, key)
		if err != nil {
			return nil, false, err
		}
	}

	for _, entry := range m.triggerRules[key] {
		var next []RuleApplication
		var nextApplied bool
		var err error
		if len(entry.rule.Triggers()) == 1 {
			next, nextApplied, err = m.handleTriggers(c, event, entry.rule)
		} else {
			if hintContinuation || anchored[entry.ordinal] {
				continue
			}
			next, nextApplied, err = m.startPending(c, event, key, entry)
		}
		if err != nil {
			return nil, false, err
		}
		applied = applied || nextApplied
		applications = append(applications, next...)
	}

	return applications, applied, nil
}

func (m *Monitor) startPending(
	c *Config,
	event term.Term,
	key ruleKey,
	entry triggerRuleEntry,
) ([]RuleApplication, bool, error) {
	if !canMatchLHS(c, m.requirements[entry.rule]) {
		return nil, false, nil
	}

	var applications []RuleApplication
	applied := false
	triggers := entry.rule.Triggers()
	for slot, trigger := range triggers {
		triggerKey, err := ruleKeyForTerm(trigger)
		if err != nil {
			return nil, false, err
		}
		if triggerKey != key {
			continue
		}
		triggerBinding, triggerErr := event.Unify(trigger)
		if triggerErr != nil &&
			!errors.Is(triggerErr, term.ErrEvaluation) &&
			!couldMatch(event, trigger, entry.lhsVariables) {
			continue
		}

		lhs := entry.rule.LHS
		if triggerErr == nil {
			lhs = make([]*rule.Fact, len(entry.rule.LHS))
			for i, fact := range entry.rule.LHS {
				lhs[i] = fact.Subst(triggerBinding)
			}
		}

		for _, lhsBinding := range conflictSetFactsForConfig(c, lhs).Values() {
			var binding *term.Binding
			if triggerErr == nil {
				binding = triggerBinding.Extend(lhsBinding)
			} else {
				instantiated := trigger.Subst(lhsBinding)
				eventBinding, err := event.Unify(instantiated)
				if err != nil {
					continue
				}
				binding = lhsBinding.Extend(eventBinding)
			}

			reserved, err := c.reserveRuleLHS(entry.rule, binding, trigger)
			if err != nil {
				return nil, false, err
			}
			applied = true
			outstanding := make([]int, 0, len(triggers)-1)
			for i := range triggers {
				if i != slot {
					outstanding = append(outstanding, i)
				}
			}
			reserved.addPending(pendingApplication{
				ruleOrdinal: entry.ordinal,
				binding:     binding,
				outstanding: outstanding,
			})
			next, err := m.handleEpsilon(entry.rule, binding.Clone(), reserved, nil)
			if err != nil {
				return nil, false, err
			}
			applications = append(applications, next...)
		}
	}

	return applications, applied, nil
}

// couldMatch reports whether pattern may match event once the premise
// variables lhsVariables are substituted. The event is compared as
// unification evaluates it; an event that cannot be evaluated is not
// compared.
func couldMatch(event, pattern term.Term, lhsVariables []*term.Variable) bool {
	evaluated, err := term.Evaluate(event)
	return err != nil || couldMatchAfterLHSSubstitution(pattern, evaluated, lhsVariables)
}

func couldMatchAfterLHSSubstitution(
	pattern term.Term,
	target term.Term,
	lhsVariables []*term.Variable,
) bool {
	// Unification binds a variable of the event to any pattern.
	if target.GetType() == term.VariableType {
		return true
	}
	switch pattern.GetType() {
	case term.VariableType:
		return true
	case term.ConstantType:
		return pattern.Equal(target)
	case term.FunctionType:
		function := term.Must(term.AsFunction(pattern))
		// A format is parsed against a constant.
		if function.Name == term.CatFunctionName && target.GetType() == term.ConstantType {
			return true
		}
		if function.MayEvalToConstant() {
			for _, variable := range term.Vars(function) {
				for _, lhsVariable := range lhsVariables {
					if variable.Equal(lhsVariable) {
						return true
					}
				}
			}
		}

		targetFunction, err := term.AsFunction(target)
		if err != nil || function.Name != targetFunction.Name || len(function.Args) != len(targetFunction.Args) {
			return false
		}
		for i := range function.Args {
			if !couldMatchAfterLHSSubstitution(function.Args[i], targetFunction.Args[i], lhsVariables) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (m *Monitor) advancePending(
	c *Config,
	event term.Term,
	key ruleKey,
) ([]RuleApplication, map[int]bool, bool, error) {
	var applications []RuleApplication
	anchored := make(map[int]bool)
	applied := false
	for pendingIndex, pending := range c.pending {
		// Identical entries are instances of the same start. Advancing or
		// completing any of them gives the same successor and actions, so
		// only the first is tried; the others remain for later events.
		if slices.ContainsFunc(c.pending[:pendingIndex], pending.equal) {
			continue
		}
		r := m.rules[pending.ruleOrdinal]
		triggers := r.Triggers()
		for slotPosition, slot := range pending.outstanding {
			triggerKey, err := ruleKeyForTerm(triggers[slot])
			if err != nil {
				return nil, nil, false, err
			}
			if triggerKey != key {
				continue
			}
			instantiated := triggers[slot].Subst(pending.binding)
			eventBinding, err := event.Unify(instantiated)
			if err != nil {
				continue
			}
			anchored[pending.ruleOrdinal] = true

			binding := pending.binding.Extend(eventBinding)
			outstanding := slices.Clone(pending.outstanding)
			outstanding = slices.Delete(outstanding, slotPosition, slotPosition+1)
			result := c.Clone()
			if len(outstanding) > 0 {
				result.replacePending(pendingIndex, pendingApplication{
					ruleOrdinal: pending.ruleOrdinal,
					binding:     binding,
					outstanding: outstanding,
				})
				applied = true
				next, err := m.handleEpsilon(r, binding, result, nil)
				if err != nil {
					return nil, nil, false, err
				}
				applications = append(applications, next...)
				continue
			}

			result.removePending(pendingIndex)
			result, actions, err := result.finalizeReservedRule(r, binding)
			if err != nil {
				if errors.Is(err, ErrRestrictionViolated) {
					continue
				}
				return nil, nil, false, err
			}
			applied = true
			// The completion takes the place of a split rule's end rule,
			// so it is the epsilon step of the application's last block.
			if err := m.checkEpsilonDepth(result); err != nil {
				return nil, nil, false, err
			}
			applications = append(applications, RuleApplication{
				rule: r, binding: binding, config: result, actions: actions,
			})
		}
	}
	return applications, anchored, applied, nil
}

// handleTriggers returns the applications of a rule with a single trigger
// that consume a in c. applied reports whether the rule was applied, even
// if the epsilon step that follows then ended every branch.
func (m *Monitor) handleTriggers(c *Config, a term.Term, r *rule.Rule) ([]RuleApplication, bool, error) {
	log.Tracef("handleTriggers(%s, %s, %s)\n\n", c, a, r.Name)

	rawTriggers := r.Triggers()
	if !canMatchLHS(c, m.requirements[r]) {
		return nil, false, nil
	}
	var C []RuleApplication
	applied := false

	// Try to extract a trigger binding from the event first. When this
	// succeeds, shared variables narrow the LHS fact search from O(N)
	// to O(1). Falls back to the original O(N) approach when the raw
	// trigger contains format expressions with functions of unbound
	// variables that cannot be evaluated without LHS-derived bindings.
	triggerBinding, triggerErr := a.Unify(rawTriggers[0])

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
			u, err := a.Unify(rawTriggers[0].Subst(b))
			if err != nil {
				continue
			}
			bt = b.Extend(u)
		}

		if d, acts, err := c.ApplyRule(r, bt); err == nil {
			log.Infof("rule %s is applicable\n  binding: %s", r.Name, bt)

			applied = true

			// The epsilon step follows the transition.
			next, err := m.handleEpsilon(r, bt, d, acts)
			if err != nil {
				return nil, false, err
			}
			C = append(C, next...)
		} else if errors.Is(err, ErrRestrictionViolated) {
			log.Infof("rule %s not applicable due to restriction: %v", r.Name, err)
		} else {
			return nil, false, err
		}
	}

	return C, applied, nil
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
		gKey, err := ruleKeyForTerm(g)
		if err != nil {
			return nil, fmt.Errorf("invalid event after accepting hint: %w", err)
		}

		D, applied, err := m.handleTriggerPaths(d, g, gKey, true)
		if err != nil {
			return nil, err
		}

		if len(D) == 0 {
			// A triggered rule consumed the event, but the epsilon step
			// after it ended every branch. Only this hint candidate ends.
			// Its actions are not published.
			if applied {
				continue
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

	return C, nil
}

// handleEpsilon performs the epsilon step after a transition: it applies
// the rules without triggers or hints to c.
//
// Every successful application is its own successor. Successors with the
// same configuration and actions are merged. A candidate whose
// restriction fails is skipped, so if every candidate fails there is no
// successor and only this branch ends. Without a candidate, c is the only
// successor. An epsilon candidate left in a successor is an
// ErrEpsilonDepth error.
//
// It returns one application of the transition's rule r under b per
// successor. Its actions are acts followed by those of the epsilon rule,
// so that PPEvent rewrites emitted by epsilon rules reach the rewrite
// output.
func (m *Monitor) handleEpsilon(r *rule.Rule, b *term.Binding, c *Config, acts []*rule.Fact) ([]RuleApplication, error) {
	log.Infof("\n\nhandleEpsilon()\n")

	candidates := false
	var successors []RuleApplication
	for _, e := range m.epsilonRules {
		if !canMatchLHS(c, m.requirements[e]) {
			continue
		}
		for _, eb := range conflictSetFactsForConfig(c, e.LHS).Values() {
			candidates = true
			log.Infof("epsilon rule %s is applicable\n  binding: %s", e.Name, eb)

			d, eActs, err := c.ApplyRule(e, eb)
			if err != nil {
				if errors.Is(err, ErrRestrictionViolated) {
					log.Infof("epsilon rule %s not applicable due to restriction: %v", e.Name, err)
					continue
				}
				return nil, err
			}
			actions := concatActions(acts, eActs)
			if !slices.ContainsFunc(successors, func(s RuleApplication) bool {
				return s.config.Hash() == d.Hash() && slices.EqualFunc(s.actions, actions, func(a, b *rule.Fact) bool {
					return a.Name == b.Name && a.Type == b.Type && slices.EqualFunc(a.Args, b.Args, term.EqualWithKind)
				})
			}) {
				successors = append(successors, RuleApplication{rule: r, binding: b, config: d, actions: actions})
			}
		}
	}

	if !candidates {
		return []RuleApplication{{rule: r, binding: b, config: c, actions: acts}}, nil
	}
	for _, successor := range successors {
		if err := m.checkEpsilonDepth(successor.config); err != nil {
			return nil, err
		}
	}
	return successors, nil
}

// checkEpsilonDepth returns an ErrEpsilonDepth error if an epsilon rule
// matches c after an epsilon step. It only matches premises, so it also
// finds a candidate whose restriction would fail, and it changes nothing.
func (m *Monitor) checkEpsilonDepth(c *Config) error {
	for _, r := range m.epsilonRules {
		if canMatchLHS(c, m.requirements[r]) && !conflictSetFactsForConfig(c, r.LHS).Empty() {
			return fmt.Errorf("%w: rule %s", ErrEpsilonDepth, r.Name)
		}
	}
	return nil
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

// ViolationKindNoApplicableRule is the kind of a violation in which no
// rule accepts the event.
const ViolationKindNoApplicableRule = "no_applicable_rule"

// ViolationInfo describes a violation: the rejected event, its one-based
// index among the events this monitor received, and the statistics at
// that point.
type ViolationInfo struct {
	Err        error
	ErrorKind  string
	TimedEvent *TimedEvent
	EventIndex int
	Stats      StatsSummary
}

// StreamResult is the outcome of processing an event stream: a violation,
// an error, or neither when the stream ended.
type StreamResult struct {
	Violation *ViolationInfo
	Err       error
}

// StatsSummary holds the event counts and durations of Stats in
// nanoseconds.
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

// Summary returns the counts and durations of s, with the total time
// measured up to end. It does not reorder the samples.
func (s *Stats) Summary(end time.Time) StatsSummary {
	summary := StatsSummary{Received: len(s.LatenciesReceived), Processed: len(s.LatenciesProcessed)}
	if !s.StartTime.IsZero() && !end.IsZero() {
		summary.TotalTimeNS = end.Sub(s.StartTime).Nanoseconds()
	}

	paired := min(summary.Received, summary.Processed)
	var processingTotal time.Duration
	for i := range paired {
		processingTotal += s.LatenciesProcessed[i] - s.LatenciesReceived[i]
	}
	if paired > 0 {
		summary.AvgProcessingTimeNS = (processingTotal / time.Duration(paired)).Nanoseconds()
	}

	summary.AvgLatencyReceivedNS, summary.MedLatencyReceivedNS = meanAndMedian(s.LatenciesReceived)
	summary.AvgLatencyProcessedNS, summary.MedLatencyProcessedNS = meanAndMedian(s.LatenciesProcessed)
	return summary
}

// meanAndMedian returns the mean and the median of samples in nanoseconds,
// without reordering samples.
func meanAndMedian(samples []time.Duration) (int64, int64) {
	if len(samples) == 0 {
		return 0, 0
	}
	var total time.Duration
	for _, sample := range samples {
		total += sample
	}
	median := time.Duration(utils.MedianDuration(slices.Clone(samples)))
	return (total / time.Duration(len(samples))).Nanoseconds(), median.Nanoseconds()
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

			applications, err := m.processEvent(event.Event)
			if err != nil {
				if errors.Is(err, ErrNoApplicableRule) {
					result.Violation = &ViolationInfo{
						Err:        err,
						ErrorKind:  ViolationKindNoApplicableRule,
						TimedEvent: cloneTimedEvent(event),
						EventIndex: len(m.stats.LatenciesReceived),
						Stats:      m.stats.Summary(time.Now()),
					}
				} else {
					result.Err = fmt.Errorf("process event %s: %w", event.Event, err)
				}
				return
			}

			m.stats.LatenciesProcessed = append(m.stats.LatenciesProcessed, time.Since(time.Unix(0, event.Time)))

			if rewrite {
				outputs, err := rewriteOutputSequence(event.Event, applications)
				if err != nil {
					result.Err = err
					return
				}
				for _, output := range outputs {
					select {
					case out <- &TimedEvent{Time: event.Time, Event: output}:
					case <-ctx.Done():
						result.Err = ctx.Err()
						return
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

// cloneTimedEvent copies the event of a violation. The copy gives every
// function a non-nil argument list, so that the event of a violation
// encodes a function without arguments with "args": [].
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
	case *term.Constant[int64]:
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

// rewriteOutputSequence returns the events that the rule applications for
// one raw event emit. The caller supplies at least one application. As in
// the integrated pipeline, identical sequences are emitted once. Different
// sequences would be separate branches, which a single output stream cannot
// represent, so they are an error.
func rewriteOutputSequence(event term.Term, applications []RuleApplication) ([]*term.Function, error) {
	var sequences [][]*term.Function
	for _, application := range applications {
		outputs, err := rewriteOutputs(application.actions)
		if err != nil {
			return nil, err
		}
		for _, output := range outputs {
			if err := checkRewriteEvent(output); err != nil {
				return nil, fmt.Errorf("invalid rewritten event: %w", err)
			}
		}
		if !slices.ContainsFunc(sequences, func(sequence []*term.Function) bool {
			return outputsEqual(sequence, outputs)
		}) {
			sequences = append(sequences, outputs)
		}
	}
	if len(sequences) > 1 {
		return nil, fmt.Errorf("%w: the rule applications for %.120s emit %d different event sequences. "+
			"specmon monitor -R keeps them apart as separate branches", ErrNondeterministicRewrite, event, len(sequences))
	}
	return sequences[0], nil
}

// CheckWellformedness checks if the rules are well-formed.
func checkWellformedness(rules []*rule.Rule) error {
	for _, r := range rules {
		for _, action := range r.Act {
			call, _ := term.SplitPair(action.RewriteTerm())
			if fn, ok := call.(*term.Function); ok && fn != nil && forbiddenRewriteHead(fn.Name) {
				return fmt.Errorf("rule %s: built-in %s cannot name a rewritten event", r.Name, fn.Name)
			}
		}
		// A hint rule must have a non-empty LHS.
		if r.HasHints() && len(r.LHS) == 0 {
			return fmt.Errorf("hint rule %s has empty LHS", r.Name)
		}
	}

	return checkEpsilonRules(rules)
}

// checkEpsilonRules checks a static condition under which the epsilon step
// of a transition leaves no epsilon candidate behind:
//
//  1. No epsilon rule has a premise that an epsilon step can produce. The
//     conclusions of epsilon rules count as produced, and so do those of
//     every rule with a computation, since the canonical split form
//     produces them in the rule's end rule. A conclusion matches a premise
//     with its name and arity. The split state that the end rule of a
//     decomposed rule consumes comes from the other split rules of that
//     rule and does not count.
//  2. Every epsilon rule has a linear premise, so that its application
//     disables it.
//
// The condition does not exclude two independent epsilon candidates in one
// configuration. The depth check at run time (checkEpsilonDepth) catches
// those.
func checkEpsilonRules(rules []*rule.Rule) error {
	type producer struct {
		rule    string
		epsilon bool
	}
	type signature struct {
		name  string
		arity int
	}
	producers := make(map[signature]producer)
	for _, r := range rules {
		epsilon := r.IsEpsilon()
		if !epsilon && !r.HasComputation() {
			continue
		}
		for _, f := range r.RHS {
			if rule.IsInternalFactName(f.Name) {
				continue
			}
			// An epsilon producer explains the violation more directly.
			key := signature{f.Name, len(f.Args)}
			if p, ok := producers[key]; !ok || (epsilon && !p.epsilon) {
				producers[key] = producer{rule: r.Name, epsilon: epsilon}
			}
		}
	}

	for _, r := range rules {
		if !r.IsEpsilon() {
			continue
		}
		for _, f := range r.LHS {
			p, ok := producers[signature{f.Name, len(f.Args)}]
			if !ok {
				continue
			}
			if p.epsilon {
				return fmt.Errorf("epsilon rule %s has premise %s, which epsilon rule %s produces", r.Name, f.Name, p.rule)
			}
			if r.MatchesSplitStateName(f) {
				continue
			}
			return fmt.Errorf("epsilon rule %s has premise %s, a conclusion of rule %s, "+
				"whose end rule produces it in an epsilon step in the split form", r.Name, f.Name, p.rule)
		}
		if !slices.ContainsFunc(r.LHS, (*rule.Fact).IsLinear) {
			return fmt.Errorf("epsilon rule %s has no linear premise", r.Name)
		}
	}
	return nil
}

// splitPairSignature returns the (name, arity) of the first component of
// a hint/trigger pair. Used to bucket rules into triggerRules / hintRules
// so dispatch is by (name, arity) rather than name only.
func splitPairSignature(t term.Term) (string, int, error) {
	fn, _ := term.SplitPair(t)
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

// forbiddenRewriteHead applies only to emitted calls. Pair-headed calls
// and built-ins nested in a call's arguments remain valid.
func forbiddenRewriteHead(name string) bool {
	return name != term.PairFunctionName && term.ReservedNames.Contains(name)
}

func checkRewriteEvent(output term.Term) error {
	call, _ := term.SplitPair(output)
	fn, ok := call.(*term.Function)
	if !ok || fn == nil {
		if call == nil {
			return fmt.Errorf("expected event pair, got %s", output)
		}
		return fmt.Errorf("expected event function, got %s", call)
	}
	if forbiddenRewriteHead(fn.Name) {
		return fmt.Errorf("built-in %s cannot name a rewritten event", fn.Name)
	}
	return nil
}
