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
	// epsilon step of a transition. The branch that reaches such a
	// configuration is pruned.
	ErrEpsilonDepth = errors.New("epsilon rule applicable after an epsilon step")
	// ErrNondeterministicRewrite reports that the rule applications for one
	// event emit different event sequences, which a single output stream
	// cannot represent.
	ErrNondeterministicRewrite = errors.New("nondeterministic rewrite")
)

// ruleKey identifies the predicate-name + arity an event term carries.
// Splitting trigger and hint rule dispatch by (name, arity) lets us skip
// the HasTriggers/HasHints filter in the hot loop and avoids visiting
// rules that pattern-match the same name with a different arity.
type ruleKey struct {
	name  string
	arity int
}

// ruleEntry is a rule with a trigger or hint of one key, with its index in
// the rules of the monitor. lhsVariables, the premise variables, are set
// for a rule with several triggers and for a hint rule: a pattern that
// does not match an event can match once they are substituted only if it
// contains one of them.
type ruleEntry struct {
	ordinal      int
	rule         *rule.Rule
	lhsVariables []*term.Variable
}

// Monitor is a monitor that processes events according to a set of rules.
type Monitor struct {
	// triggerRules maps event (name, arity) to rules whose triggers
	// contain a term with that signature. Pre-filtered so hot-loop
	// callers don't repeat HasTriggers().
	triggerRules map[ruleKey][]ruleEntry

	// hintRules maps event (name, arity) to rules whose hints contain a
	// term with that signature. Pre-filtered so hot-loop callers don't
	// repeat HasHints().
	hintRules map[ruleKey][]ruleEntry

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

	// rejected holds the configurations from which the last event was
	// rejected, after which configs is empty. Only the diagnostics read
	// it. It never becomes live again.
	rejected *data.HashSet[*Config]

	// stats includes the statistics of the monitor.
	stats *Stats

	// failures keeps the records of failed candidates and branches. The
	// pipeline shares the log of its core monitor with its rewriter.
	failures *failureLog
	// site is where the records of the current event are made.
	site failureSite
}

// computeRequirements returns a lower bound on each predicate's stored
// occurrences. Linear premises count separately. Persistent premises of
// one name count once because matching may reuse the same stored fact.
func computeRequirements(lhs []*rule.Fact) map[string]int {
	if len(lhs) == 0 {
		return nil
	}
	needCount := make(map[string]int, len(lhs))
	for i, f := range lhs {
		if f == nil || f.IsPersistent() && slices.ContainsFunc(lhs[:i], func(g *rule.Fact) bool {
			return g != nil && g.IsPersistent() && g.Name == f.Name
		}) {
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
	return newMonitor(rules)
}

// newMonitor returns a monitor for rules without checking that they are
// admitted. Only tests of the invariants that admission ensures use it
// directly.
func newMonitor(rules []*rule.Rule) (*Monitor, error) {
	triggerRules := make(map[ruleKey][]ruleEntry)
	hintRules := make(map[ruleKey][]ruleEntry)
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
				triggerRules[k] = append(triggerRules[k], ruleEntry{
					ordinal:      ordinal,
					rule:         r,
					lhsVariables: lhsVariables,
				})
			}
		}
		if hasHints {
			entry := ruleEntry{ordinal: ordinal, rule: r, lhsVariables: rule.Facts(r.LHS).Vars()}
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
				hintRules[k] = append(hintRules[k], entry)
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
		failures:     &failureLog{},
		site:         failureSite{monitor: FailureMonitorCore},
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
//
// A candidate that fails ends only its own branch. If no branch is left,
// the error is ErrNoApplicableRule and no configuration stays live, so
// every later event is rejected as well.
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

	m.beginEvent()
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
		m.logAllowedEvents(m.configs.Values(), func(i int) string { return fmt.Sprintf("allowed events in configuration %d", i) })

		// No branch survives the event, so none stays live. The
		// configurations before it are kept for the diagnostics only.
		if !m.configs.Empty() {
			m.rejected = m.configs
		}
		m.configs = updated
		return nil, ErrNoApplicableRule
	}

	m.configs = updated

	return applied, nil
}

// processConfigEvent returns every transition that consumes event from c.
// It does not mutate m.configs, which keeps a rewrite configuration paired
// with only the downstream configurations reached through that rewrite path.
//
// A failed candidate ends only its own branch and is recorded. The error
// result is reserved for broken invariants. If no transition consumes the
// event and no candidate recorded a failure, the branch is recorded as
// ended without a candidate.
func (m *Monitor) processConfigEvent(c *Config, event term.Term, key ruleKey) ([]RuleApplication, error) {
	m.site.branch = c
	recorded := len(m.failures.current)
	appliedTriggers, err := m.handleTriggerPaths(c, event, key, false)
	if err != nil {
		return nil, err
	}

	var appliedHints []RuleApplication
	for _, entry := range m.hintRules[key] {
		next, err := m.handleHints(c, event, entry)
		if err != nil {
			return nil, err
		}

		for _, hinted := range next {
			// One valid direct continuation from the same family with an
			// equal binding is enough to suppress the hinted start. This
			// is decided for each hint binding, so a suppressed
			// alternative does not suppress another one.
			if slices.ContainsFunc(appliedTriggers, func(direct RuleApplication) bool {
				return rule.IsStartRuleOf(entry.rule, direct.rule) && direct.binding.Equal(hinted.binding)
			}) {
				continue
			}
			appliedHints = append(appliedHints, hinted)
		}
	}

	appliedTriggers = append(appliedTriggers, appliedHints...)
	if len(appliedTriggers) == 0 && len(m.failures.current) == recorded {
		m.recordFailure(FailureNoCandidate, "", "no rule candidate consumes the event", nil)
	}
	return appliedTriggers, nil
}

// logAllowedEvents logs the events that each of configs allows, under the
// heading that label gives for its index.
func (m *Monitor) logAllowedEvents(configs []*Config, label func(int) string) {
	for i, events := range m.possibleEvents(configs) {
		log.Errorf("%s:\n", label(i))
		for _, e := range events {
			log.Errorf("  %.120s\n", e)
		}
	}
}

// possibleEvents returns the events that are possible in each of configs.
func (m *Monitor) possibleEvents(configs []*Config) [][]term.Term {
	events := make([][]term.Term, len(configs))

	for i, c := range configs {
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

// handleTriggerPaths returns the applications of the trigger rules and
// pending applications that consume event in c. A hint continuation uses
// only rules with a single trigger: it neither starts nor advances a
// pending application of a rule with several triggers.
func (m *Monitor) handleTriggerPaths(c *Config, event term.Term, key ruleKey, hintContinuation bool) ([]RuleApplication, error) {
	var applications []RuleApplication
	var anchored map[int]bool
	if !hintContinuation {
		var err error
		applications, anchored, err = m.advancePending(c, event, key)
		if err != nil {
			return nil, err
		}
	}

	for _, entry := range m.triggerRules[key] {
		var next []RuleApplication
		var err error
		if len(entry.rule.Triggers()) == 1 {
			next, err = m.handleTriggers(c, event, entry.rule)
		} else {
			if hintContinuation || anchored[entry.ordinal] {
				continue
			}
			next, err = m.startPending(c, event, key, entry)
		}
		if err != nil {
			return nil, err
		}
		applications = append(applications, next...)
	}

	return applications, nil
}

func (m *Monitor) startPending(
	c *Config,
	event term.Term,
	key ruleKey,
	entry ruleEntry,
) ([]RuleApplication, error) {
	if !canMatchLHS(c, m.requirements[entry.rule]) {
		return nil, nil
	}

	var applications []RuleApplication
	triggers := entry.rule.Triggers()
	for slot, trigger := range triggers {
		triggerKey, err := ruleKeyForTerm(trigger)
		if err != nil {
			return nil, err
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

		for _, lhsBinding := range premiseCandidates(c, entry.rule, triggerBinding, triggerErr).Values() {
			eventBinding, err := event.Unify(trigger.Subst(lhsBinding))
			if err != nil {
				continue
			}
			binding := lhsBinding.Extend(eventBinding)

			reserved, err := c.reserveRuleLHS(entry.rule, binding, trigger)
			if err != nil {
				if m.recordLocalFailure(entry.rule, err) {
					continue
				}
				return nil, err
			}
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
				return nil, err
			}
			applications = append(applications, next...)
		}
	}

	return applications, nil
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
) ([]RuleApplication, map[int]bool, error) {
	var applications []RuleApplication
	var anchored map[int]bool
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
				return nil, nil, err
			}
			if triggerKey != key {
				continue
			}
			instantiated := triggers[slot].Subst(pending.binding)
			eventBinding, err := event.Unify(instantiated)
			if err != nil {
				continue
			}
			if anchored == nil {
				anchored = make(map[int]bool)
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
				next, err := m.handleEpsilon(r, binding, result, nil)
				if err != nil {
					return nil, nil, err
				}
				applications = append(applications, next...)
				continue
			}

			result.removePending(pendingIndex)
			result, actions, err := result.finalizeReservedRule(r, binding)
			if err != nil {
				if m.recordLocalFailure(r, err) {
					continue
				}
				return nil, nil, err
			}
			// The completion takes the place of a split rule's end rule,
			// so it is the epsilon step of the application's last block.
			// A completion that leaves an epsilon candidate is pruned on
			// its own. As after a failed completion, the start of this
			// rule that its match suppressed stays suppressed.
			if err := m.checkEpsilonDepth(result); err != nil {
				m.recordLocalFailure(r, err)
				continue
			}
			applications = append(applications, RuleApplication{
				rule: r, binding: binding, config: result, actions: actions,
			})
		}
	}
	return applications, anchored, nil
}

// handleTriggers returns the applications of a rule with a single trigger
// that consume a in c.
func (m *Monitor) handleTriggers(c *Config, a term.Term, r *rule.Rule) ([]RuleApplication, error) {
	log.Tracef("handleTriggers(%s, %s, %s)\n\n", c, a, r.Name)

	rawTriggers := r.Triggers()
	if !canMatchLHS(c, m.requirements[r]) {
		return nil, nil
	}
	var C []RuleApplication

	// The premises are matched first and the trigger under their values,
	// so that premise variables take the values of their facts. A trigger
	// that matches the event as it is only narrows the facts that the
	// premises are matched against.
	triggerBinding, triggerErr := a.Unify(rawTriggers[0])
	for _, b := range premiseCandidates(c, r, triggerBinding, triggerErr).Values() {
		u, err := a.Unify(rawTriggers[0].Subst(b))
		if err != nil {
			continue
		}
		bt := b.Extend(u)

		d, acts, err := c.ApplyRule(r, bt)
		if err != nil {
			if m.recordLocalFailure(r, err) {
				log.Infof("rule %s not applicable: %v", r.Name, err)
				continue
			}
			return nil, err
		}
		log.Infof("rule %s is applicable\n  binding: %s", r.Name, bt)

		// The epsilon step follows the transition.
		next, err := m.handleEpsilon(r, bt, d, acts)
		if err != nil {
			return nil, err
		}
		C = append(C, next...)
	}

	return C, nil
}

// handleHints returns the applications of the hint rule of entry that
// consume the event in the configuration.
// Every hint binding, together with a premise
// substitution, is an alternative of its own: the hinted start is applied
// under it, and every rule with a single trigger that consumes the event in the
// hinted state continues it. An alternative without such a continuation
// is a dead hint. It gives no application, and its actions are not
// published.
func (m *Monitor) handleHints(config *Config, event term.Term, entry ruleEntry) ([]RuleApplication, error) {
	hintRule := entry.rule
	log.Tracef("handleHints(%s, %s, %s)\n\n", config, event, hintRule.Name)

	if !canMatchLHS(config, m.requirements[hintRule]) {
		return nil, nil
	}
	var applications []RuleApplication

	for _, hintBinding := range m.hintBindings(config, event, entry) {
		log.Infof("hint rule %s is applicable\n  binding: %s", hintRule.Name, hintBinding)

		hintConfig, hintActions, err := config.ApplyRule(hintRule, hintBinding)
		if err != nil {
			if m.recordLocalFailure(hintRule, err) {
				log.Infof("hint rule %s not applicable: %v", hintRule.Name, err)
				continue
			}
			return nil, err
		}

		// Each hint binding attempts its own trigger continuations.
		continuationEvent := event.Subst(hintBinding)
		continuationKey, err := ruleKeyForTerm(continuationEvent)
		if err != nil {
			return nil, fmt.Errorf("invalid event after accepting hint: %w", err)
		}
		continuations, err := m.handleTriggerPaths(hintConfig, continuationEvent, continuationKey, true)
		if err != nil {
			return nil, err
		}
		if len(continuations) == 0 {
			m.recordFailure(FailureDeadHint, hintRule.Name, "no continuation consumes the event after accepting hint", nil)
			continue
		}

		for _, continuation := range continuations {
			// Concatenate hint actions and downstream trigger actions.
			// concatActions allocates only when both sides are non-empty,
			// so the common single-source case stays alloc-free and we
			// avoid aliasing hintActions across iterations.
			applications = append(applications, RuleApplication{rule: hintRule, binding: hintBinding, config: continuation.config, actions: concatActions(hintActions, continuation.actions)})
		}
	}

	return applications, nil
}

// premiseCandidates returns the premise substitutions of r in c. If an
// annotation of r matched the event as it is (annotationErr is nil), only
// the facts that agree with its binding u are tried. The substitutions
// still come from the premises alone (conflictSetFactsNarrowed), so every
// premise variable takes the value of its fact.
func premiseCandidates(c *Config, r *rule.Rule, u *term.Binding, annotationErr error) *bindingSet {
	if annotationErr != nil {
		return conflictSetFactsForConfig(c, r.LHS)
	}
	narrowed := make([]*rule.Fact, len(r.LHS))
	for i, f := range r.LHS {
		narrowed[i] = f.Subst(u)
	}
	return conflictSetFactsNarrowed(c, r.LHS, narrowed)
}

// hintBindings returns the distinct bindings under which a hint of the
// rule r of entry matches a in c, each extended by a premise substitution
// of r.
//
// If the hints that match a as they are agree on one binding, the facts
// that the premises are matched against are narrowed by it. The bindings
// still come from the premises first, then from a hint under them, as with
// distinct bindings. A hint that does not match a may still match once
// its premise variables are substituted, if its evaluation failed or if
// its terms allow it. If there is such a hint, every hint is then matched
// against a again for each premise substitution. Without a binding, or
// with distinct ones, every hint is matched for each premise substitution.
// Both ways find the same bindings for one hint, and every distinct
// binding is kept. Equal bindings of several hints count once.
func (m *Monitor) hintBindings(c *Config, a term.Term, entry ruleEntry) []*term.Binding {
	r := entry.rule
	var direct *term.Binding
	var directHint term.Term
	ambiguous, substituted := false, false
	for _, hint := range r.Hints() {
		u, err := a.Unify(hint)
		if err != nil {
			substituted = substituted || errors.Is(err, term.ErrEvaluation) || couldMatch(a, hint, entry.lhsVariables)
			continue
		}
		if direct == nil {
			direct, directHint = u, hint
		} else if !direct.Equal(u) {
			ambiguous = true
		}
	}
	if direct == nil || ambiguous {
		return m.hintBindingsPerPremise(c, a, r, nil)
	}

	// The hints that match directly agree on one binding, so each of them
	// gives the same binding under a premise substitution as directHint.
	var bindings []*term.Binding
	for _, b := range premiseCandidates(c, r, direct, nil).Values() {
		if u, err := a.Unify(directHint.Subst(b)); err == nil {
			bindings = append(bindings, b.Extend(u))
		}
	}
	if !substituted {
		return bindings
	}
	return m.hintBindingsPerPremise(c, a, r, bindings)
}

// hintBindingsPerPremise appends to bindings the distinct bindings under
// which a hint of r matches a after a premise substitution, in the order
// of the substitutions and then of the hints.
func (m *Monitor) hintBindingsPerPremise(c *Config, a term.Term, r *rule.Rule, bindings []*term.Binding) []*term.Binding {
	seen := newBindingSet()
	for _, hb := range bindings {
		seen.Add(hb)
	}
	for _, b := range conflictSetFactsForConfig(c, r.LHS).Values() {
		for _, hint := range r.Hints() {
			u, err := a.Unify(hint.Subst(b))
			if err != nil {
				continue
			}
			if hb := b.Extend(u); seen.Add(hb) {
				bindings = append(bindings, hb)
			}
		}
	}
	return bindings
}

// handleEpsilon performs the epsilon step after a transition: it applies
// the rules without triggers or hints to c.
//
// Every successful application is its own successor. Successors with the
// same configuration and actions are merged. A candidate whose
// restriction or evaluation fails is skipped, so if every candidate fails
// there is no successor and only this branch ends. Without a candidate, c
// is the only successor. A successor in which an epsilon candidate is
// left is pruned on its own. The error result is reserved for broken
// invariants.
//
// It returns one application of the transition's rule r under b per
// successor. Its actions are acts followed by those of the epsilon rule,
// so that PPEvent rewrites emitted by epsilon rules reach the rewrite
// output.
func (m *Monitor) handleEpsilon(r *rule.Rule, b *term.Binding, c *Config, acts []*rule.Fact) ([]RuleApplication, error) {
	log.Infof("\n\nhandleEpsilon()\n")

	candidates := false
	var successors []RuleApplication
	var epsilons []*rule.Rule
	for _, e := range m.epsilonRules {
		if !canMatchLHS(c, m.requirements[e]) {
			continue
		}
		for _, eb := range conflictSetFactsForConfig(c, e.LHS).Values() {
			candidates = true
			log.Infof("epsilon rule %s is applicable\n  binding: %s", e.Name, eb)

			d, eActs, err := c.ApplyRule(e, eb)
			if err != nil {
				if m.recordLocalFailure(e, err) {
					log.Infof("epsilon rule %s not applicable: %v", e.Name, err)
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
				epsilons = append(epsilons, e)
			}
		}
	}

	if !candidates {
		return []RuleApplication{{rule: r, binding: b, config: c, actions: acts}}, nil
	}
	valid := successors[:0]
	for i, successor := range successors {
		if err := m.checkEpsilonDepth(successor.config); err != nil {
			m.recordLocalFailure(epsilons[i], err)
			continue
		}
		valid = append(valid, successor)
	}
	return valid, nil
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
	// Failures reports the failed candidates and branches of the rejected
	// event and of earlier events.
	Failures FailureReport
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
						Failures:   m.failures.report(),
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

// logFinalConfigs logs the live configurations or, after a rejected event,
// those from which the event was rejected.
func (m *Monitor) logFinalConfigs() {
	configs := m.configs
	if configs.Empty() && m.rejected != nil {
		configs = m.rejected
	}
	log.Warnf("\nfinal configurations (%d)\n", configs.Size())
	for _, c := range configs.Values() {
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
		// A hint rule must have a non-empty LHS.
		if r.HasHints() && len(r.LHS) == 0 {
			return fmt.Errorf("hint rule %s has empty LHS", r.Name)
		}
		if err := checkRuleAdmission(r); err != nil {
			return err
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
//     produces them in the rule's end rule. So do those of an end rule
//     fused with the rule of its last computation, which consumes an
//     event but is an epsilon rule in the canonical split form. It is
//     named after its source rule with the end rule suffix and consumes
//     split-state facts. A conclusion matches a premise with its name and
//     arity. The split state that the end rule of a decomposed rule
//     consumes comes from the other split rules of that rule and does not
//     count.
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
		name := r.Name
		if !epsilon && !r.HasComputation() {
			if !slices.ContainsFunc(r.LHS, r.MatchesSplitStateName) {
				continue
			}
			name = strings.TrimSuffix(r.Name, rule.ComponentSep+rule.EndRuleSuffix)
		}
		for _, f := range r.RHS {
			if rule.IsInternalFactName(f.Name) {
				continue
			}
			// An epsilon producer explains the violation more directly.
			key := signature{f.Name, len(f.Args)}
			if p, ok := producers[key]; !ok || (epsilon && !p.epsilon) {
				producers[key] = producer{rule: name, epsilon: epsilon}
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
