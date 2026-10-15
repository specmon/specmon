// Copyright (C) 2026 CISPA Helmholtz Center for Information Security
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
	"errors"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

type multiTriggerReferenceFamily struct {
	sourceOrdinal int
	starts        []*rule.Rule
	continuations []*rule.Rule
}

type multiTriggerReferenceScenario struct {
	nativeRules []*rule.Rule
	// state are the variables known after the first step of each native
	// rule with several triggers. Without referenceRules, the reference
	// replaces each such rule by handDesugaredRules(rule, state).
	state                []term.Term
	referenceRules       []*rule.Rule
	referenceFamilies    []multiTriggerReferenceFamily
	initialFacts         []*rule.Fact
	hiddenReferenceFacts map[string]struct{}
	events               []term.Term
	wantReferenceActions map[int][]string
	wantReferenceConfigs map[int][]string
	wantReferenceErrors  map[int]string
}

func runMultiTriggerReferenceScenario(t *testing.T, scenario multiTriggerReferenceScenario) {
	t.Helper()
	if scenario.referenceRules == nil {
		scenario.hiddenReferenceFacts = make(map[string]struct{})
		for ordinal, native := range scenario.nativeRules {
			if len(native.Triggers()) < 2 {
				scenario.referenceRules = append(scenario.referenceRules, native)
				continue
			}
			reference, hidden := handDesugaredRules(native, scenario.state)
			starts := len(native.Triggers())
			scenario.referenceRules = append(scenario.referenceRules, reference...)
			scenario.referenceFamilies = append(scenario.referenceFamilies, multiTriggerReferenceFamily{
				sourceOrdinal: ordinal, starts: reference[:starts], continuations: reference[starts:],
			})
			maps.Copy(scenario.hiddenReferenceFacts, hidden)
		}
	}

	native, err := NewMonitor(scenario.nativeRules)
	if err != nil {
		t.Fatalf("NewMonitor(native): %v", err)
	}
	reference, err := NewMonitor(scenario.referenceRules)
	if err != nil {
		t.Fatalf("NewMonitor(reference): %v", err)
	}
	for _, fact := range scenario.initialFacts {
		native.Configs()[0].AddFact(fact)
		reference.Configs()[0].AddFact(fact)
	}

	for step, event := range scenario.events {
		nativeActions, nativeErr := native.ProcessEvent(event)
		referenceActions, referenceErr := processPrioritizedReferenceEvent(
			reference, event, scenario.referenceFamilies,
		)

		gotNativeConfigs := publicConfigProjection(native, nil)
		gotReferenceConfigs := publicConfigProjection(reference, scenario.hiddenReferenceFacts)
		if !slices.Equal(gotNativeConfigs, gotReferenceConfigs) {
			t.Errorf("step %d, event %s: public configs differ\n native:    %q\n reference: %q",
				step, event, gotNativeConfigs, gotReferenceConfigs)
		}

		gotNativeActions := actionProjection(nativeActions)
		gotReferenceActions := actionProjection(referenceActions)
		if !slices.Equal(gotNativeActions, gotReferenceActions) {
			t.Errorf("step %d, event %s: action groups differ\n native:    %q\n reference: %q",
				step, event, gotNativeActions, gotReferenceActions)
		}

		nativeCategory := monitorErrorCategory(nativeErr)
		referenceCategory := monitorErrorCategory(referenceErr)
		if nativeCategory != referenceCategory {
			t.Errorf("step %d, event %s: error category = %q, want reference %q",
				step, event, nativeCategory, referenceCategory)
		}
		if want, ok := scenario.wantReferenceActions[step]; ok && !slices.Equal(gotReferenceActions, want) {
			t.Errorf("step %d, event %s: reference actions = %q, want %q",
				step, event, gotReferenceActions, want)
		}
		if want, ok := scenario.wantReferenceConfigs[step]; ok && !slices.Equal(gotReferenceConfigs, want) {
			t.Errorf("step %d, event %s: reference configs = %q, want %q",
				step, event, gotReferenceConfigs, want)
		}
		if want, ok := scenario.wantReferenceErrors[step]; ok && referenceCategory != want {
			t.Errorf("step %d, event %s: reference error category = %q, want %q",
				step, event, referenceCategory, want)
		}

		if referenceErr == nil {
			for i, config := range reference.Configs() {
				if len(config.seen) != 0 {
					t.Errorf("step %d, event %s: reference config %d retained seen events: %v",
						step, event, i, config.seen)
				}
			}
		}
		if nativeErr != nil || referenceErr != nil {
			return
		}
	}
}

type multiTriggerReferenceRole struct {
	sourceOrdinal int
	start         bool
}

func processPrioritizedReferenceEvent(
	m *Monitor,
	event term.Term,
	families []multiTriggerReferenceFamily,
) ([][]*rule.Fact, error) {
	key, err := ruleKeyForTerm(event)
	if err != nil {
		return nil, err
	}

	roles := make(map[*rule.Rule]multiTriggerReferenceRole)
	for _, family := range families {
		for _, r := range family.starts {
			roles[r] = multiTriggerReferenceRole{sourceOrdinal: family.sourceOrdinal, start: true}
		}
		for _, r := range family.continuations {
			roles[r] = multiTriggerReferenceRole{sourceOrdinal: family.sourceOrdinal}
		}
	}

	updated := data.NewHashSet[*Config]()
	var actions [][]*rule.Fact
	for _, config := range m.configs.Values() {
		applications, err := prioritizedReferenceApplications(m, config, event, key, roles)
		if err != nil {
			return nil, err
		}
		for _, application := range applications {
			updated.Add(application.config)
			if len(application.actions) > 0 {
				actions = append(actions, application.actions)
			}
		}
	}
	if updated.Empty() {
		return nil, ErrNoApplicableRule
	}
	m.configs = updated
	return actions, nil
}

func prioritizedReferenceApplications(
	m *Monitor,
	config *Config,
	event term.Term,
	key ruleKey,
	roles map[*rule.Rule]multiTriggerReferenceRole,
) ([]RuleApplication, error) {
	type candidate struct {
		application RuleApplication
		role        multiTriggerReferenceRole
		generated   bool
	}

	anchored := make(map[int]bool)
	var candidates []candidate
	for _, entry := range m.triggerRules[key] {
		role, generated := roles[entry.rule]
		if generated && !role.start {
			matched := referenceContinuationAnchored(config, event, entry.rule)
			if matched {
				anchored[role.sourceOrdinal] = true
			}
		}

		next, _, err := m.handleTriggers(config, event, entry.rule)
		if err != nil {
			return nil, err
		}
		for _, application := range next {
			candidates = append(candidates, candidate{
				application: application,
				role:        role,
				generated:   generated,
			})
		}
	}

	var applications []RuleApplication
	for _, candidate := range candidates {
		if candidate.generated && candidate.role.start && anchored[candidate.role.sourceOrdinal] {
			continue
		}
		applications = append(applications, candidate.application)
	}
	for _, r := range m.hintRules[key] {
		next, err := m.handleHints(config, event, r)
		if err != nil {
			return nil, err
		}
		applications = append(applications, next...)
	}
	return applications, nil
}

func referenceContinuationAnchored(config *Config, event term.Term, r *rule.Rule) bool {
	if !canMatchLHS(config, computeRequirements(r.LHS)) {
		return false
	}

	rawTriggers := r.Triggers()
	triggerBinding, triggerErr := event.Unify(rawTriggers[0])

	lhsPatterns := r.LHS
	if triggerErr == nil {
		lhsPatterns = make([]*rule.Fact, len(r.LHS))
		for i, fact := range r.LHS {
			lhsPatterns[i] = fact.Subst(triggerBinding)
		}
	}
	for _, lhsBinding := range conflictSetFactsForConfig(config, lhsPatterns).Values() {
		if triggerErr == nil {
			// Compatibility here is the hand-desugared counterpart of successfully
			// unifying a native pending trigger after substituting its stored binding.
			if triggerBinding.Compatible(lhsBinding) {
				return true
			}
			continue
		}
		if _, err := event.Unify(rawTriggers[0].Subst(lhsBinding)); err == nil {
			return true
		}
	}
	return false
}

func publicConfigProjection(m *Monitor, hidden map[string]struct{}) []string {
	configs := make([]string, 0, len(m.Configs()))
	for _, config := range m.Configs() {
		facts := make([]string, 0, len(config.Facts()))
		for _, fact := range config.Facts() {
			if _, ok := hidden[fact.Name]; ok {
				continue
			}
			facts = append(facts, fact.String())
		}
		sort.Strings(facts)

		seen := make([]string, len(config.seen))
		for i, event := range config.seen {
			seen[i] = event.String()
		}
		sort.Strings(seen)
		configs = append(configs, strings.Join(facts, "\x1e")+"\x1d"+strings.Join(seen, "\x1e"))
	}
	sort.Strings(configs)
	return configs
}

func factProjection(facts ...*rule.Fact) string {
	projected := make([]string, len(facts))
	for i, fact := range facts {
		projected[i] = fact.String()
	}
	sort.Strings(projected)
	return strings.Join(projected, "\x1e") + "\x1d"
}

func actionProjection(groups [][]*rule.Fact) []string {
	projected := make([]string, len(groups))
	for i, group := range groups {
		facts := make([]string, len(group))
		for j, fact := range group {
			facts[j] = fact.String()
		}
		projected[i] = strings.Join(facts, "\x1e")
	}
	sort.Strings(projected)
	return projected
}

func monitorErrorCategory(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoApplicableRule):
		return ViolationKindNoApplicableRule
	case errors.Is(err, ErrRestrictionViolated):
		return "restriction"
	case errors.Is(err, term.ErrEvaluation):
		return "evaluation"
	default:
		return "internal"
	}
}

func eventTerm(name string, value term.Term) *term.Function {
	return term.NewFunction(term.PairFunctionName, []term.Term{
		term.NewFunction(name, nil),
		value,
	})
}

func triggerRule(
	name string,
	lhs []*rule.Fact,
	rhs []*rule.Fact,
	actions []*rule.Fact,
	triggers ...term.Term,
) *rule.Rule {
	return &rule.Rule{
		Name: name,
		LHS:  lhs,
		RHS:  rhs,
		Act:  actions,
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: triggers},
		},
	}
}

func epsilonRule(name string, lhs, rhs, actions []*rule.Fact) *rule.Rule {
	return &rule.Rule{Name: name, LHS: lhs, RHS: rhs, Act: actions, Attrs: map[string]rule.Attribute{}}
}

// handDesugaredRules expands a native multi-trigger rule into explicit
// single-trigger transitions. Each nonempty outstanding-slot bit set gets a
// distinct linear fact, so trigger slots retain their original identities.
// state contains exactly the variables known after every possible first step.
func handDesugaredRules(native *rule.Rule, state []term.Term) ([]*rule.Rule, map[string]struct{}) {
	pendingPrefix := native.Name + "ReferencePending"
	triggers := native.Triggers()
	full := 1<<len(triggers) - 1
	hidden := make(map[string]struct{}, full-1)
	pending := func(mask int) *rule.Fact {
		name := pendingPrefix + strconv.Itoa(mask)
		hidden[name] = struct{}{}
		return rule.NewFact(name, state, rule.LinearFact)
	}

	rules := make([]*rule.Rule, 0, len(triggers)*full)
	for slot, trigger := range triggers {
		remaining := full &^ (1 << slot)
		rules = append(rules, triggerRule(
			native.Name+"ReferenceStart"+strconv.Itoa(slot),
			native.LHS,
			[]*rule.Fact{pending(remaining)},
			nil,
			trigger,
		))
	}
	for outstanding := 1; outstanding < full; outstanding++ {
		for slot, trigger := range triggers {
			if outstanding&(1<<slot) == 0 {
				continue
			}
			remaining := outstanding &^ (1 << slot)
			rhs := native.RHS
			actions := native.Act
			if remaining != 0 {
				rhs = []*rule.Fact{pending(remaining)}
				actions = nil
			}
			rules = append(rules, triggerRule(
				native.Name+"ReferenceAdvance"+strconv.Itoa(outstanding)+"Slot"+strconv.Itoa(slot),
				[]*rule.Fact{pending(outstanding)},
				rhs,
				actions,
				trigger,
			))
		}
	}
	return rules, hidden
}

// acceptEvents creates a monitor with rules, adds facts to its initial
// configuration and processes events, which must all be accepted. It
// returns the actions of the last event.
func acceptEvents(t *testing.T, rules []*rule.Rule, facts []*rule.Fact, events ...term.Term) (*Monitor, [][]*rule.Fact) {
	t.Helper()
	m, err := NewMonitor(rules)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	for _, fact := range facts {
		m.Configs()[0].AddFact(fact)
	}
	var actions [][]*rule.Fact
	for _, event := range events {
		if actions, err = m.ProcessEvent(event); err != nil {
			t.Fatalf("ProcessEvent(%s): %v", event, err)
		}
	}
	return m, actions
}

// wantConfigs checks the projection of m's configurations, in any order
// of want.
func wantConfigs(t *testing.T, m *Monitor, want ...string) {
	t.Helper()
	want = slices.Clone(want)
	sort.Strings(want)
	if got := publicConfigProjection(m, nil); !slices.Equal(got, want) {
		t.Errorf("configurations = %q, want %q", got, want)
	}
}

func TestMultiTriggerReferenceAcceptsEveryArrivalOrder(t *testing.T) {
	const (
		readyFactName    = "MultiOrderReady"
		finishedFactName = "MultiOrderFinished"
		firstEventName   = "multiOrderFirst"
		secondEventName  = "multiOrderSecond"
		thirdEventName   = "multiOrderThird"
	)

	value := term.NewVariable("value")
	triggers := []term.Term{
		eventTerm(firstEventName, value),
		eventTerm(secondEventName, value),
		eventTerm(thirdEventName, value),
	}
	native := triggerRule(
		"MultiOrder",
		[]*rule.Fact{rule.NewFact(readyFactName, []term.Term{value}, rule.LinearFact)},
		[]*rule.Fact{rule.NewFact(finishedFactName, []term.Term{value}, rule.LinearFact)},
		nil,
		triggers...,
	)
	input := term.NewConstant("session")
	events := []term.Term{
		eventTerm(firstEventName, input),
		eventTerm(secondEventName, input),
		eventTerm(thirdEventName, input),
	}
	orders := [][]int{
		{0, 1, 2},
		{0, 2, 1},
		{1, 0, 2},
		{1, 2, 0},
		{2, 0, 1},
		{2, 1, 0},
	}
	for _, order := range orders {
		name := strconv.Itoa(order[0]) + strconv.Itoa(order[1]) + strconv.Itoa(order[2])
		t.Run(name, func(t *testing.T) {
			runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
				nativeRules:  []*rule.Rule{native},
				state:        []term.Term{value},
				initialFacts: []*rule.Fact{rule.NewFact(readyFactName, []term.Term{input}, rule.LinearFact)},
				events:       []term.Term{events[order[0]], events[order[1]], events[order[2]]},
			})
		})
	}
}

func TestMultiTriggerReferenceReservesLinearFacts(t *testing.T) {
	const (
		resourceFactName = "MultiReserveResource"
		finishedFactName = "MultiReserveFinished"
		stolenFactName   = "MultiReserveStolen"
		startEventName   = "multiReserveStart"
		finishEventName  = "multiReserveFinish"
		competeEventName = "multiReserveCompete"
	)

	unit := term.NewFunction(term.PairFunctionName, nil)
	resource := rule.NewFact(resourceFactName, nil, rule.LinearFact)
	native := triggerRule(
		"MultiReserve",
		[]*rule.Fact{resource},
		[]*rule.Fact{rule.NewFact(finishedFactName, nil, rule.LinearFact)},
		nil,
		eventTerm(startEventName, unit),
		eventTerm(finishEventName, unit),
	)
	competing := triggerRule(
		"MultiReserveCompeting",
		[]*rule.Fact{resource},
		[]*rule.Fact{rule.NewFact(stolenFactName, nil, rule.LinearFact)},
		nil,
		eventTerm(competeEventName, unit),
	)
	runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
		nativeRules:  []*rule.Rule{native, competing},
		initialFacts: []*rule.Fact{resource},
		events: []term.Term{
			eventTerm(startEventName, unit),
			eventTerm(competeEventName, unit),
		},
		wantReferenceErrors: map[int]string{1: ViolationKindNoApplicableRule},
	})
}

func TestMultiTriggerReferencePreservesCandidateMultiplicity(t *testing.T) {
	const (
		candidateFactName = "MultiCandidate"
		finishedFactName  = "MultiCandidateFinished"
		startEventName    = "multiCandidateStart"
		finishEventName   = "multiCandidateFinish"
	)

	for _, factType := range []rule.FactType{rule.LinearFact, rule.PersistentFact} {
		t.Run(string(factType), func(t *testing.T) {
			value := term.NewVariable("value")
			unit := term.NewFunction(term.PairFunctionName, nil)
			native := triggerRule(
				"MultiCandidateRule",
				[]*rule.Fact{rule.NewFact(candidateFactName, []term.Term{value}, factType)},
				[]*rule.Fact{rule.NewFact(finishedFactName, []term.Term{value}, rule.LinearFact)},
				nil,
				eventTerm(startEventName, unit),
				eventTerm(finishEventName, value),
			)
			one := term.NewConstant[int64](1)
			two := term.NewConstant[int64](2)

			runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
				nativeRules: []*rule.Rule{native},
				state:       []term.Term{value},
				initialFacts: []*rule.Fact{
					rule.NewFact(candidateFactName, []term.Term{one}, factType),
					rule.NewFact(candidateFactName, []term.Term{two}, factType),
				},
				events: []term.Term{
					eventTerm(startEventName, unit),
					eventTerm(finishEventName, one),
				},
			})
		})
	}
}

// TestMultiTriggerReferenceCompletesIdenticalInstancesOnce checks that two
// starts under the same binding are two instances: one completion consumes
// one of them with a single application, and a second completion the other.
func TestMultiTriggerReferenceCompletesIdenticalInstancesOnce(t *testing.T) {
	const (
		tokenFactName   = "MultiIdenticalToken"
		emitFactName    = "MultiIdenticalEmit"
		startEventName  = "multiIdenticalStart"
		finishEventName = "multiIdenticalFinish"
	)

	value := term.NewVariable("value")
	unit := term.NewFunction(term.PairFunctionName, nil)
	one := term.NewConstant[int64](1)
	emit := rule.NewFact(emitFactName, nil, rule.LinearFact)
	for _, test := range []struct {
		name    string
		lhs     []*rule.Fact
		state   []term.Term
		initial []*rule.Fact
		finish  term.Term
	}{
		{name: "without premises", finish: unit},
		{
			name:  "equal linear premises",
			lhs:   []*rule.Fact{rule.NewFact(tokenFactName, []term.Term{value}, rule.LinearFact)},
			state: []term.Term{value},
			initial: []*rule.Fact{
				rule.NewFact(tokenFactName, []term.Term{one}, rule.LinearFact),
				rule.NewFact(tokenFactName, []term.Term{one}, rule.LinearFact),
			},
			finish: value,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			native := triggerRule("MultiIdentical", test.lhs, nil, []*rule.Fact{emit},
				eventTerm(startEventName, unit), eventTerm(finishEventName, test.finish))
			finish := eventTerm(finishEventName, test.finish.Subst(bindingOf(value, one)))
			runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
				nativeRules:          []*rule.Rule{native},
				state:                test.state,
				initialFacts:         test.initial,
				events:               []term.Term{eventTerm(startEventName, unit), eventTerm(startEventName, unit), finish, finish},
				wantReferenceActions: map[int][]string{2: {emitFactName + "()"}, 3: {emitFactName + "()"}},
			})
		})
	}
}

func bindingOf(v *term.Variable, value term.Term) *term.Binding {
	b := term.NewBinding()
	b.Set(v, value)
	return b
}

func TestMultiTriggerReferenceBindsLHSBeforeEvaluatingTrigger(t *testing.T) {
	const (
		candidateFactName = "MultiEvaluatedCandidate"
		finishedFactName  = "MultiEvaluatedFinished"
		computedEventName = "multiEvaluatedComputed"
		finishEventName   = "multiEvaluatedFinish"
	)

	value := term.NewVariable("value")
	one := term.NewConstant[int64](1)
	two := term.NewConstant[int64](2)
	computed := term.NewFunction(term.AddFunctionName, []term.Term{value, one})
	native := triggerRule(
		"MultiEvaluated",
		[]*rule.Fact{rule.NewFact(candidateFactName, []term.Term{value}, rule.LinearFact)},
		[]*rule.Fact{rule.NewFact(finishedFactName, []term.Term{value}, rule.LinearFact)},
		nil,
		eventTerm(computedEventName, computed),
		eventTerm(finishEventName, value),
	)

	runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
		nativeRules: []*rule.Rule{native},
		state:       []term.Term{value},
		initialFacts: []*rule.Fact{
			rule.NewFact(candidateFactName, []term.Term{one}, rule.LinearFact),
		},
		events: []term.Term{
			eventTerm(computedEventName, two),
			eventTerm(finishEventName, one),
		},
	})
}

// TestMultiTriggerReferenceRunsEpsilonAfterTransitions checks that the
// epsilon step follows the start of a native multi-trigger application,
// as it follows the corresponding transition of the hand-desugared rules,
// and never runs before the reservation. Start and advance produce no
// facts, so only epsilon candidates present before the start can fire.
// The completion is itself an epsilon step. See
// TestMultiTriggerCompletionIsEpsilonStep.
func TestMultiTriggerReferenceRunsEpsilonAfterTransitions(t *testing.T) {
	const (
		reservedFactName   = "MultiEpsilonReserved"
		stageZeroFactName  = "MultiEpsilonStageZero"
		stageOneFactName   = "MultiEpsilonStageOne"
		blockedFactName    = "MultiEpsilonBlocked"
		finishedFactName   = "MultiEpsilonFinished"
		originalActionName = "MultiEpsilonOriginalAction"
		startActionName    = "MultiEpsilonStartAction"
		firstEventName     = "multiEpsilonFirst"
		secondEventName    = "multiEpsilonSecond"
		thirdEventName     = "multiEpsilonThird"
	)

	unit := term.NewFunction(term.PairFunctionName, nil)
	native := triggerRule(
		"MultiEpsilon",
		[]*rule.Fact{rule.NewFact(reservedFactName, nil, rule.LinearFact)},
		[]*rule.Fact{rule.NewFact(finishedFactName, nil, rule.LinearFact)},
		[]*rule.Fact{rule.NewFact(originalActionName, nil, rule.LinearFact)},
		eventTerm(firstEventName, unit),
		eventTerm(secondEventName, unit),
		eventTerm(thirdEventName, unit),
	)
	epsilonRules := []*rule.Rule{
		epsilonRule(
			"MultiEpsilonBlockedBeforeReservation",
			[]*rule.Fact{rule.NewFact(reservedFactName, nil, rule.LinearFact)},
			[]*rule.Fact{rule.NewFact(blockedFactName, nil, rule.LinearFact)},
			nil,
		),
		epsilonRule(
			"MultiEpsilonAfterStart",
			[]*rule.Fact{rule.NewFact(stageZeroFactName, nil, rule.LinearFact)},
			[]*rule.Fact{rule.NewFact(stageOneFactName, nil, rule.LinearFact)},
			[]*rule.Fact{rule.NewFact(startActionName, nil, rule.LinearFact)},
		),
	}

	runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
		nativeRules:  append([]*rule.Rule{native}, epsilonRules...),
		initialFacts: []*rule.Fact{rule.NewFact(reservedFactName, nil, rule.LinearFact), rule.NewFact(stageZeroFactName, nil, rule.LinearFact)},
		events: []term.Term{
			eventTerm(firstEventName, unit),
			eventTerm(secondEventName, unit),
			eventTerm(thirdEventName, unit),
		},
		wantReferenceActions: map[int][]string{
			0: {startActionName + "()"},
			1: {},
			2: {originalActionName + "()"},
		},
		wantReferenceConfigs: map[int][]string{
			2: {factProjection(rule.NewFact(finishedFactName, nil, rule.LinearFact), rule.NewFact(stageOneFactName, nil, rule.LinearFact))},
		},
	})
}

// TestMultiTriggerCompletionIsEpsilonStep checks that the completion of a
// native multi-trigger application is the epsilon step of its last block,
// as the end rule is for a split rule: no epsilon rule runs after it, and
// an epsilon candidate left by it is an error.
func TestMultiTriggerCompletionIsEpsilonStep(t *testing.T) {
	t.Parallel()

	const (
		reservedFactName = "MultiCompletionReserved"
		finishedFactName = "MultiCompletionFinished"
		doneFactName     = "MultiCompletionDone"
		firstEventName   = "multiCompletionFirst"
		secondEventName  = "multiCompletionSecond"
	)

	unit := term.NewFunction(term.PairFunctionName, nil)
	reserved := rule.NewFact(reservedFactName, nil, rule.LinearFact)
	finished := rule.NewFact(finishedFactName, nil, rule.LinearFact)
	native := triggerRule("MultiCompletion", []*rule.Fact{reserved}, []*rule.Fact{finished}, nil,
		eventTerm(firstEventName, unit), eventTerm(secondEventName, unit))

	after := epsilonRule("MultiCompletionAfter", []*rule.Fact{finished},
		[]*rule.Fact{rule.NewFact(doneFactName, nil, rule.LinearFact)}, nil)
	m := newEpsilonTestMonitor(t, native, after)
	m.Configs()[0].AddFact(reserved)
	if _, err := m.ProcessEvent(eventTerm(firstEventName, unit)); err != nil {
		t.Fatalf("ProcessEvent(start): %v", err)
	}
	if _, err := m.ProcessEvent(eventTerm(secondEventName, unit)); !errors.Is(err, ErrEpsilonDepth) {
		t.Fatalf("ProcessEvent(completion) error = %v, want ErrEpsilonDepth", err)
	}
}

// TestHintContinuationUsesSingleTriggerRules checks that a hint
// continuation consumes the event only with rules with a single trigger:
// it neither starts nor advances a native multi-trigger application. The
// hint candidate then has no continuation, which is an error.
func TestHintContinuationUsesSingleTriggerRules(t *testing.T) {
	t.Parallel()

	const (
		hintReadyFactName = "MultiHintReady"
		hintDoneFactName  = "MultiHintDone"
		resourceFactName  = "MultiHintResource"
		finishedFactName  = "MultiHintFinished"
		startEventName    = "multiHintStart"
		finishEventName   = "multiHintFinish"
	)

	unit := term.NewFunction(term.PairFunctionName, nil)
	startEvent := eventTerm(startEventName, unit)
	finishEvent := eventTerm(finishEventName, unit)
	resource := rule.NewFact(resourceFactName, nil, rule.LinearFact)
	hintReady := rule.NewFact(hintReadyFactName, nil, rule.LinearFact)
	native := triggerRule("MultiHint", []*rule.Fact{resource},
		[]*rule.Fact{rule.NewFact(finishedFactName, nil, rule.LinearFact)}, nil, startEvent, finishEvent)
	hint := func(event term.Term, rhs *rule.Fact) *rule.Rule {
		return &rule.Rule{
			Name: "MultiHintSetup",
			LHS:  []*rule.Fact{hintReady},
			RHS:  []*rule.Fact{rhs},
			Attrs: map[string]rule.Attribute{
				rule.HintAttributeName: rule.TermAttribute{Value: []term.Term{event}},
			},
		}
	}

	for _, test := range []struct {
		name   string
		hint   *rule.Rule
		facts  []*rule.Fact
		events []term.Term
	}{
		{
			// The hint provides the resource that a start would reserve.
			name:   "no start",
			hint:   hint(startEvent, resource),
			facts:  []*rule.Fact{hintReady},
			events: []term.Term{startEvent},
		},
		{
			// The application is started directly. The hint's
			// continuation could complete it.
			name:   "no advance",
			hint:   hint(finishEvent, rule.NewFact(hintDoneFactName, nil, rule.LinearFact)),
			facts:  []*rule.Fact{hintReady, resource},
			events: []term.Term{startEvent, finishEvent},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			m := newEpsilonTestMonitor(t, native, test.hint)
			for _, fact := range test.facts {
				m.Configs()[0].AddFact(fact)
			}
			last := len(test.events) - 1
			for _, event := range test.events[:last] {
				if _, err := m.ProcessEvent(event); err != nil {
					t.Fatalf("ProcessEvent(%s): %v", event, err)
				}
			}
			_, err := m.ProcessEvent(test.events[last])
			if !errors.Is(err, ErrNoApplicableRule) || !strings.Contains(err.Error(), "after accepting hint") {
				t.Fatalf("ProcessEvent error = %v, want no continuation after the hint", err)
			}
		})
	}
}

// TestMultiTriggerReferenceStartsAfterPremiseSubstitution checks starts
// whose trigger matches the event only once a premise variable is
// substituted, beside a part that the event matches as unification
// compares it: a format parsed from bytes, a variable of the event, and
// a computation in the event.
func TestMultiTriggerReferenceStartsAfterPremiseSubstitution(t *testing.T) {
	k := term.NewVariable("multiSubstitutedK")
	one := term.NewConstant[int64](1)
	three := term.NewConstant[int64](3)
	unit := term.NewFunction(term.PairFunctionName, nil)
	pair := func(a, b term.Term) term.Term { return term.NewFunction(term.PairFunctionName, []term.Term{a, b}) }
	add := func(a, b term.Term) term.Term { return term.NewFunction(term.AddFunctionName, []term.Term{a, b}) }
	state := func(v term.Term) *rule.Fact {
		return rule.NewFact("MultiSubstitutedState", []term.Term{v}, rule.LinearFact)
	}
	done := func(v term.Term) *rule.Fact {
		return rule.NewFact("MultiSubstitutedDone", []term.Term{v}, rule.LinearFact)
	}
	format := term.NewFunction(term.CatFunctionName, []term.Term{
		term.NewFunction(string(term.FormatByteType), []term.Term{term.NewVariable("multiSubstitutedX")}),
	})

	for _, test := range []struct {
		name         string
		trigger, got term.Term
	}{
		{name: "format", trigger: pair(format, add(k, one)), got: pair(term.NewConstant([]byte{0x07}), three)},
		{name: "event variable", trigger: pair(term.NewConstant("c"), add(k, one)), got: pair(term.NewVariable("multiSubstitutedV"), three)},
		{name: "event computation", trigger: pair(three, add(k, one)), got: pair(add(one, term.NewConstant[int64](2)), three)},
	} {
		t.Run(test.name, func(t *testing.T) {
			native := triggerRule("MultiSubstituted", []*rule.Fact{state(k)}, []*rule.Fact{done(k)}, nil,
				eventTerm("multiSubstitutedGo", test.trigger), eventTerm("multiSubstitutedFinish", unit))
			two := term.NewConstant[int64](2)
			runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
				nativeRules:          []*rule.Rule{native},
				state:                []term.Term{k},
				initialFacts:         []*rule.Fact{state(two)},
				events:               []term.Term{eventTerm("multiSubstitutedGo", test.got), eventTerm("multiSubstitutedFinish", unit)},
				wantReferenceConfigs: map[int][]string{1: {factProjection(done(two))}},
			})
		})
	}
}

func TestMultiTriggerReferenceKeepsSlotIdentity(t *testing.T) {
	const (
		finishedFactName = "MultiSlotFinished"
		goEventName      = "multiSlotGo"
		pendingZeroName  = "MultiSlotReferencePendingZero"
		pendingOneName   = "MultiSlotReferencePendingOne"
	)

	value := term.NewVariable("value")
	fixed := term.NewConstant("fixed")
	other := term.NewConstant("other")
	native := triggerRule(
		"MultiSlot",
		nil,
		[]*rule.Fact{rule.NewFact(finishedFactName, []term.Term{value}, rule.LinearFact)},
		nil,
		eventTerm(goEventName, value),
		eventTerm(goEventName, fixed),
	)
	reference := []*rule.Rule{
		triggerRule(
			"MultiSlotStartZero",
			nil,
			[]*rule.Fact{rule.NewFact(pendingOneName, []term.Term{value}, rule.LinearFact)},
			nil,
			eventTerm(goEventName, value),
		),
		triggerRule(
			"MultiSlotFinishOne",
			[]*rule.Fact{rule.NewFact(pendingOneName, []term.Term{value}, rule.LinearFact)},
			[]*rule.Fact{rule.NewFact(finishedFactName, []term.Term{value}, rule.LinearFact)},
			nil,
			eventTerm(goEventName, fixed),
		),
		triggerRule(
			"MultiSlotStartOne",
			nil,
			[]*rule.Fact{rule.NewFact(pendingZeroName, nil, rule.LinearFact)},
			nil,
			eventTerm(goEventName, fixed),
		),
		triggerRule(
			"MultiSlotFinishZero",
			[]*rule.Fact{rule.NewFact(pendingZeroName, nil, rule.LinearFact)},
			[]*rule.Fact{rule.NewFact(finishedFactName, []term.Term{value}, rule.LinearFact)},
			nil,
			eventTerm(goEventName, value),
		),
	}
	hidden := map[string]struct{}{pendingZeroName: {}, pendingOneName: {}}
	referenceFamily := multiTriggerReferenceFamily{
		sourceOrdinal: 0,
		starts:        []*rule.Rule{reference[0], reference[2]},
		continuations: []*rule.Rule{reference[1], reference[3]},
	}

	runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
		nativeRules:          []*rule.Rule{native},
		referenceRules:       reference,
		referenceFamilies:    []multiTriggerReferenceFamily{referenceFamily},
		hiddenReferenceFacts: hidden,
		events: []term.Term{
			eventTerm(goEventName, fixed),
			eventTerm(goEventName, other),
		},
	})
}

// TestNewMonitorRegistersSameSignatureTriggersOnce checks that a rule with
// several triggers of one key is registered once under that key. Through
// ProcessEvent a second registration is hard to observe: its starts reach
// configurations equal to those of the first, which merge.
func TestNewMonitorRegistersSameSignatureTriggersOnce(t *testing.T) {
	const eventName = "multiSameKeyGo"
	x := term.NewVariable("x")
	y := term.NewVariable("y")
	m, err := NewMonitor([]*rule.Rule{
		triggerRule("MultiSameKey", nil, nil, nil, eventTerm(eventName, x), eventTerm(eventName, y)),
	})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	key, err := ruleKeyForTerm(eventTerm(eventName, x))
	if err != nil {
		t.Fatalf("ruleKeyForTerm: %v", err)
	}
	if got := len(m.triggerRules[key]); got != 1 {
		t.Fatalf("rule registered %d times under its trigger key, want once", got)
	}
}

func TestHandDesugaredReferencePreservesDistinctActionPaths(t *testing.T) {
	const (
		finishedFactName = "MultiPathFinished"
		actionFactName   = "MultiPathEmit"
		goEventName      = "multiPathGo"
		pendingXName     = "MultiPathReferencePendingX"
		pendingYName     = "MultiPathReferencePendingY"
	)

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	a := term.NewConstant("A")
	b := term.NewConstant("B")
	finished := rule.NewFact(finishedFactName, nil, rule.LinearFact)
	action := rule.NewFact(actionFactName, []term.Term{x, y}, rule.LinearFact)
	reference := []*rule.Rule{
		triggerRule(
			"MultiPathStartX",
			nil,
			[]*rule.Fact{rule.NewFact(pendingYName, []term.Term{x}, rule.LinearFact)},
			nil,
			eventTerm(goEventName, x),
		),
		triggerRule(
			"MultiPathFinishY",
			[]*rule.Fact{rule.NewFact(pendingYName, []term.Term{x}, rule.LinearFact)},
			[]*rule.Fact{finished},
			[]*rule.Fact{action},
			eventTerm(goEventName, y),
		),
		triggerRule(
			"MultiPathStartY",
			nil,
			[]*rule.Fact{rule.NewFact(pendingXName, []term.Term{y}, rule.LinearFact)},
			nil,
			eventTerm(goEventName, y),
		),
		triggerRule(
			"MultiPathFinishX",
			[]*rule.Fact{rule.NewFact(pendingXName, []term.Term{y}, rule.LinearFact)},
			[]*rule.Fact{finished},
			[]*rule.Fact{action},
			eventTerm(goEventName, x),
		),
	}

	want := []string{
		rule.NewFact(actionFactName, []term.Term{a, b}, rule.LinearFact).String(),
		rule.NewFact(actionFactName, []term.Term{b, a}, rule.LinearFact).String(),
	}
	sort.Strings(want)
	// The native rule binds disjoint variables in its two slots, which
	// handDesugaredRules cannot express, so the reference is written out.
	runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
		nativeRules: []*rule.Rule{triggerRule(
			"MultiPath", nil, []*rule.Fact{finished}, []*rule.Fact{action},
			eventTerm(goEventName, x), eventTerm(goEventName, y),
		)},
		referenceRules: reference,
		referenceFamilies: []multiTriggerReferenceFamily{{
			sourceOrdinal: 0,
			starts:        []*rule.Rule{reference[0], reference[2]},
			continuations: []*rule.Rule{reference[1], reference[3]},
		}},
		hiddenReferenceFacts: map[string]struct{}{pendingXName: {}, pendingYName: {}},
		events:               []term.Term{eventTerm(goEventName, a), eventTerm(goEventName, b)},
		wantReferenceActions: map[int][]string{1: want},
	})
}

func TestMultiTriggerReferenceCompletionFailures(t *testing.T) {
	const (
		resourceFactName = "MultiFailureResource"
		invalidFactName  = "MultiFailureInvalid"
		startEventName   = "multiFailureStart"
		finishEventName  = "multiFailureFinish"
	)

	unit := term.NewFunction(term.PairFunctionName, nil)
	invalid := term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant[int64](1)})
	tests := []struct {
		name      string
		rhs       []*rule.Fact
		actions   []*rule.Fact
		wantError string
	}{
		{
			name:      "restriction",
			actions:   []*rule.Fact{rule.NewFact("Eq", []term.Term{term.NewConstant("left"), term.NewConstant("right")}, rule.LinearFact)},
			wantError: ViolationKindNoApplicableRule,
		},
		{
			name:      "invalid RHS",
			rhs:       []*rule.Fact{rule.NewFact(invalidFactName, []term.Term{invalid}, rule.LinearFact)},
			wantError: "evaluation",
		},
		{
			name:      "invalid action",
			actions:   []*rule.Fact{rule.NewFact(invalidFactName, []term.Term{invalid}, rule.LinearFact)},
			wantError: "evaluation",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			native := triggerRule(
				"MultiFailure",
				[]*rule.Fact{rule.NewFact(resourceFactName, nil, rule.LinearFact)},
				test.rhs,
				test.actions,
				eventTerm(startEventName, unit),
				eventTerm(finishEventName, unit),
			)
			runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
				nativeRules:  []*rule.Rule{native},
				initialFacts: []*rule.Fact{rule.NewFact(resourceFactName, nil, rule.LinearFact)},
				events: []term.Term{
					eventTerm(startEventName, unit),
					eventTerm(finishEventName, unit),
				},
				wantReferenceErrors: map[int]string{1: test.wantError},
			})
		})
	}
}

func TestMultiTriggerReferenceKeepsIndependentPendingWork(t *testing.T) {
	const (
		firstFinishedFactName  = "MultiIndependentFirstFinished"
		secondFinishedFactName = "MultiIndependentSecondFinished"
		firstStartEventName    = "multiIndependentFirstStart"
		firstFinishEventName   = "multiIndependentFirstFinish"
		secondStartEventName   = "multiIndependentSecondStart"
		secondFinishEventName  = "multiIndependentSecondFinish"
	)

	unit := term.NewFunction(term.PairFunctionName, nil)
	first := triggerRule(
		"MultiIndependentFirst",
		nil,
		[]*rule.Fact{rule.NewFact(firstFinishedFactName, nil, rule.LinearFact)},
		nil,
		eventTerm(firstStartEventName, unit),
		eventTerm(firstFinishEventName, unit),
	)
	second := triggerRule(
		"MultiIndependentSecond",
		nil,
		[]*rule.Fact{rule.NewFact(secondFinishedFactName, nil, rule.LinearFact)},
		nil,
		eventTerm(secondStartEventName, unit),
		eventTerm(secondFinishEventName, unit),
	)

	runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
		nativeRules: []*rule.Rule{first, second},
		events: []term.Term{
			eventTerm(firstStartEventName, unit),
			eventTerm(secondStartEventName, unit),
			eventTerm(firstFinishEventName, unit),
			eventTerm(secondFinishEventName, unit),
		},
	})
}

func TestMultiTriggerReferenceContinuationPriority(t *testing.T) {
	const (
		candidateFactName = "MultiPriorityCandidate"
		doneFactName      = "MultiPriorityDone"
		firstEventName    = "multiPriorityFirst"
		secondEventName   = "multiPrioritySecond"
	)

	x := term.NewVariable("priorityX")
	y := term.NewVariable("priorityY")
	one := term.NewConstant[int64](1)
	two := term.NewConstant[int64](2)
	three := term.NewConstant[int64](3)
	four := term.NewConstant[int64](4)
	candidate := func(left, right term.Term) *rule.Fact {
		return rule.NewFact(candidateFactName, []term.Term{left, right}, rule.LinearFact)
	}
	done := func(left, right term.Term) *rule.Fact {
		return rule.NewFact(doneFactName, []term.Term{left, right}, rule.LinearFact)
	}
	native := triggerRule(
		"MultiPriority",
		[]*rule.Fact{candidate(x, y)},
		[]*rule.Fact{done(x, y)},
		nil,
		eventTerm(firstEventName, x),
		eventTerm(secondEventName, y),
	)

	t.Run("anchored advance suppresses another binding", func(t *testing.T) {
		remaining := candidate(three, two).String() + "\x1d"
		completed := strings.Join([]string{candidate(three, two).String(), done(one, two).String()}, "\x1e") + "\x1d"
		runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
			nativeRules:  []*rule.Rule{native},
			state:        []term.Term{x, y},
			initialFacts: []*rule.Fact{candidate(one, two), candidate(three, two)},
			events: []term.Term{
				eventTerm(firstEventName, one),
				eventTerm(secondEventName, two),
			},
			wantReferenceConfigs: map[int][]string{0: {remaining}, 1: {completed}},
		})
	})

	t.Run("mismatch permits a new start", func(t *testing.T) {
		runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
			nativeRules:  []*rule.Rule{native},
			state:        []term.Term{x, y},
			initialFacts: []*rule.Fact{candidate(one, two), candidate(three, four)},
			events: []term.Term{
				eventTerm(firstEventName, one),
				eventTerm(firstEventName, three),
			},
			wantReferenceConfigs: map[int][]string{1: {"\x1d"}},
		})
	})

	t.Run("every anchored application advances", func(t *testing.T) {
		firstDone := done(one, two).String() + "\x1d"
		secondDone := done(three, two).String() + "\x1d"
		runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
			nativeRules:  []*rule.Rule{native},
			state:        []term.Term{x, y},
			initialFacts: []*rule.Fact{candidate(one, two), candidate(three, two)},
			events: []term.Term{
				eventTerm(firstEventName, one),
				eventTerm(firstEventName, three),
				eventTerm(secondEventName, two),
			},
			wantReferenceConfigs: map[int][]string{2: {firstDone, secondDone}},
		})
	})

	t.Run("restriction failure does not restore a start", func(t *testing.T) {
		restricted := triggerRule(
			"MultiPriorityRestricted",
			[]*rule.Fact{candidate(x, y)},
			nil,
			[]*rule.Fact{rule.NewFact("Eq", []term.Term{x, y}, rule.LinearFact)},
			eventTerm(firstEventName, x),
			eventTerm(firstEventName, y),
		)
		runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
			nativeRules:  []*rule.Rule{restricted},
			state:        []term.Term{x, y},
			initialFacts: []*rule.Fact{candidate(one, two), candidate(two, two)},
			events: []term.Term{
				eventTerm(firstEventName, one),
				eventTerm(firstEventName, two),
			},
			wantReferenceErrors: map[int]string{1: ViolationKindNoApplicableRule},
		})
	})
}

func TestMultiTriggerReferenceCandidateEvaluationPriority(t *testing.T) {
	const (
		candidateFactName = "MultiPriorityEvaluationCandidate"
		sharedEventName   = "multiPriorityEvaluationShared"
		startEventName    = "multiPriorityEvaluationStart"
		finishEventName   = "multiPriorityEvaluationFinish"
	)

	value := term.NewVariable("priorityEvaluationValue")
	future := term.NewVariable("priorityEvaluationFuture")
	one := term.NewConstant[int64](1)
	two := term.NewConstant[int64](2)
	invalid := term.NewFunction(term.AddFunctionName, []term.Term{future})
	candidate := func(input term.Term) *rule.Fact {
		return rule.NewFact(candidateFactName, []term.Term{input}, rule.LinearFact)
	}

	t.Run("failed continuation evaluation permits a valid start", func(t *testing.T) {
		native := triggerRule(
			"MultiPriorityEvaluationFallback",
			[]*rule.Fact{candidate(value)},
			nil,
			nil,
			eventTerm(sharedEventName, value),
			eventTerm(sharedEventName, invalid),
		)
		runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
			nativeRules:  []*rule.Rule{native},
			state:        []term.Term{value},
			initialFacts: []*rule.Fact{candidate(one), candidate(two)},
			events: []term.Term{
				eventTerm(sharedEventName, one),
				eventTerm(sharedEventName, two),
			},
			wantReferenceConfigs: map[int][]string{1: {"\x1d"}},
		})
	})

	t.Run("failed continuation evaluation leaves no successor", func(t *testing.T) {
		native := triggerRule(
			"MultiPriorityEvaluationTerminal",
			[]*rule.Fact{candidate(value)},
			nil,
			nil,
			eventTerm(startEventName, value),
			eventTerm(finishEventName, invalid),
		)
		runMultiTriggerReferenceScenario(t, multiTriggerReferenceScenario{
			nativeRules:  []*rule.Rule{native},
			state:        []term.Term{value},
			initialFacts: []*rule.Fact{candidate(one)},
			events: []term.Term{
				eventTerm(startEventName, one),
				eventTerm(finishEventName, two),
			},
			wantReferenceErrors: map[int]string{1: "no_applicable_rule"},
		})
	})
}

func TestHintContinuationPriority(t *testing.T) {
	value := term.NewVariable("hintPriorityValue")
	eventValue := term.NewVariable("hintPriorityEventValue")
	one := term.NewConstant[int64](1)
	two := term.NewConstant[int64](2)
	seven := term.NewConstant[int64](7)
	good := term.NewConstant("good")
	bad := term.NewConstant("bad")
	fact := func(name string) func(term.Term) *rule.Fact {
		return func(input term.Term) *rule.Fact { return rule.NewFact(name, []term.Term{input}, rule.LinearFact) }
	}
	seed, obligation, done := fact("HintPrioritySeed"), fact("HintPriorityObligation"), fact("HintPriorityDone")
	event := func(value term.Term) term.Term { return eventTerm("hintPriorityEvent", value) }
	unrelatedDone := rule.NewFact("HintPriorityUnrelatedDone", nil, rule.LinearFact)

	for _, test := range []struct {
		name    string
		event   term.Term
		hint    term.Term
		trigger term.Term
		actions []*rule.Fact
		extra   []*rule.Rule
		facts   []*rule.Fact
		want    []string
	}{
		{
			name:  "compatible continuation suppresses its hinted start",
			event: event(one), hint: event(value), trigger: event(value),
			facts: []*rule.Fact{seed(one), obligation(one)},
			want:  []string{factProjection(done(one), seed(one))},
		},
		{
			name:  "one compatible continuation wins beside unrelated direct rules",
			event: event(one), hint: event(value), trigger: event(value),
			extra: []*rule.Rule{triggerRule("HintPriorityUnrelated", nil, []*rule.Fact{unrelatedDone}, nil, event(value))},
			facts: []*rule.Fact{seed(one), obligation(one)},
			want:  []string{factProjection(done(one), seed(one)), factProjection(obligation(one), seed(one), unrelatedDone)},
		},
		{
			name:  "binding incompatibility preserves hinted successors",
			event: event(seven), hint: event(eventValue), trigger: event(eventValue),
			facts: []*rule.Fact{seed(two), obligation(one)},
			want: []string{
				factProjection(done(one), seed(two)),
				factProjection(done(one), obligation(two)),
				factProjection(done(two), obligation(one)),
			},
		},
		{
			name:  "direct restriction failure does not suppress a valid hint",
			event: event(seven), hint: event(eventValue), trigger: event(eventValue),
			actions: []*rule.Fact{rule.NewFact("Eq", []term.Term{value, good}, rule.LinearFact)},
			facts:   []*rule.Fact{seed(good), obligation(bad)},
			want:    []string{factProjection(done(good), obligation(bad))},
		},
		{
			name:  "direct evaluation failure does not suppress a valid hint",
			event: event(two), hint: event(two),
			trigger: event(term.NewFunction(term.AddFunctionName, []term.Term{value, one})),
			facts:   []*rule.Fact{seed(one), obligation(bad)},
			want:    []string{factProjection(done(one), obligation(bad))},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			start := &rule.Rule{
				Name:  "HintPriority_Start",
				LHS:   []*rule.Fact{seed(value)},
				RHS:   []*rule.Fact{obligation(value)},
				Attrs: map[string]rule.Attribute{rule.HintAttributeName: rule.TermAttribute{Value: []term.Term{test.hint}}},
			}
			continuation := triggerRule("HintPriority_0", []*rule.Fact{obligation(value)}, []*rule.Fact{done(value)}, test.actions, test.trigger)
			m, _ := acceptEvents(t, append([]*rule.Rule{start, continuation}, test.extra...), test.facts, test.event)
			wantConfigs(t, m, test.want...)
		})
	}
}

func TestHintFirstComputationsRemainUnordered(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	seed := rule.NewFact("HintOrderSeed", nil, rule.LinearFact)
	pending := rule.NewFact("HintOrderPending", nil, rule.LinearFact)
	done := rule.NewFact("HintOrderDone", nil, rule.LinearFact)
	first := eventTerm("hintOrderFirst", unit)
	second := eventTerm("hintOrderSecond", unit)
	start := &rule.Rule{
		Name:  "HintOrder_Start",
		LHS:   []*rule.Fact{seed},
		RHS:   []*rule.Fact{pending},
		Attrs: map[string]rule.Attribute{rule.HintAttributeName: rule.TermAttribute{Value: []term.Term{first, second}}},
	}
	continuations := []*rule.Rule{
		triggerRule("HintOrder_0", []*rule.Fact{pending}, []*rule.Fact{done}, nil, first),
		triggerRule("HintOrder_1", []*rule.Fact{pending}, []*rule.Fact{done}, nil, second),
	}
	for _, event := range []term.Term{first, second} {
		m, _ := acceptEvents(t, append([]*rule.Rule{start}, continuations...), []*rule.Fact{seed}, event)
		wantConfigs(t, m, factProjection(done))
	}
}

func TestHintCandidateEvaluationFailuresDoNotMatch(t *testing.T) {
	value := term.NewVariable("hintEvaluationValue")
	one := term.NewConstant[int64](1)
	two := term.NewConstant[int64](2)
	invalid := term.NewFunction(term.AddFunctionName, []term.Term{value})
	event := eventTerm("hintEvaluation", two)
	direct := triggerRule(
		"HintEvaluation_0",
		[]*rule.Fact{rule.NewFact("HintEvaluationDirect", []term.Term{value}, rule.LinearFact)},
		nil,
		nil,
		eventTerm("hintEvaluation", invalid),
	)
	hinted := &rule.Rule{
		Name: "HintEvaluation_Start",
		LHS:  []*rule.Fact{rule.NewFact("HintEvaluationStart", []term.Term{value}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			rule.HintAttributeName: rule.TermAttribute{Value: []term.Term{eventTerm("hintEvaluation", invalid)}},
		},
	}
	mon, err := NewMonitor([]*rule.Rule{direct, hinted})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	mon.Configs()[0].AddFact(rule.NewFact("HintEvaluationDirect", []term.Term{one}, rule.LinearFact))
	mon.Configs()[0].AddFact(rule.NewFact("HintEvaluationStart", []term.Term{one}, rule.LinearFact))
	if _, err := mon.ProcessEvent(event); !errors.Is(err, ErrNoApplicableRule) {
		t.Fatalf("ProcessEvent error = %v, want no applicable rule", err)
	}
}

// TestFindPossibleEventsSubstitutesRuleAttributes checks that the allowed
// events are the triggers and hints of each rule under its premise
// bindings, and the outstanding triggers of each pending application under
// its binding.
func TestFindPossibleEventsSubstitutesRuleAttributes(t *testing.T) {
	value := term.NewVariable("possibleValue")
	input := term.NewConstant("expected")
	state := func(v term.Term) *rule.Fact { return rule.NewFact("PossibleState", []term.Term{v}, rule.LinearFact) }
	r := triggerRule("PossibleRule", []*rule.Fact{state(value)}, nil, nil, eventTerm("possibleTrigger", value))
	r.Attrs[rule.HintAttributeName] = rule.TermAttribute{Value: []term.Term{eventTerm("possibleHint", value)}}
	native := triggerRule("MultiPossible", nil, nil, nil,
		eventTerm("multiPossibleFirst", value), eventTerm("multiPossibleSecond", value))
	m, _ := acceptEvents(t, []*rule.Rule{r, native}, []*rule.Fact{state(input)}, eventTerm("multiPossibleFirst", input))

	var possible []term.Term
	for _, events := range m.findPossibleEvents() {
		possible = append(possible, events...)
	}
	for _, want := range []term.Term{
		eventTerm("possibleHint", input),
		eventTerm("possibleTrigger", input),
		eventTerm("multiPossibleSecond", input),
	} {
		if !slices.ContainsFunc(possible, want.Equal) {
			t.Errorf("possible events %v do not contain %s", possible, want)
		}
	}
}

func TestPendingRuleIdentityUsesInputOrdinal(t *testing.T) {
	const (
		startEventName  = "multiOrdinalStart"
		finishEventName = "multiOrdinalFinish"
	)

	unit := term.NewFunction(term.PairFunctionName, nil)
	r := triggerRule(
		"MultiOrdinal",
		nil,
		nil,
		[]*rule.Fact{rule.NewFact("MultiOrdinalAction", nil, rule.LinearFact)},
		eventTerm(startEventName, unit),
		eventTerm(finishEventName, unit),
	)
	_, actions := acceptEvents(t, []*rule.Rule{r, r}, nil, eventTerm(startEventName, unit), eventTerm(finishEventName, unit))
	if got := actionProjection(actions); !slices.Equal(got, []string{
		"MultiOrdinalAction()", "MultiOrdinalAction()",
	}) {
		t.Fatalf("completion actions = %q, want one per stable input ordinal", got)
	}
}

func BenchmarkSingleTriggerProcessEvent(b *testing.B) {
	const (
		stateFactName = "BenchmarkSingleState"
		eventName     = "benchmarkSingleEvent"
	)

	silenceBenchmarkLogs(b)
	unit := term.NewFunction(term.PairFunctionName, nil)
	state := rule.NewFact(stateFactName, nil, rule.LinearFact)
	event := eventTerm(eventName, unit)
	r := triggerRule("BenchmarkSingle", []*rule.Fact{state}, []*rule.Fact{state}, nil, event)
	mon, err := NewMonitor([]*rule.Rule{r})
	if err != nil {
		b.Fatalf("NewMonitor: %v", err)
	}
	mon.Configs()[0].AddFact(state)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := mon.ProcessEvent(event); err != nil {
			b.Fatalf("ProcessEvent: %v", err)
		}
	}
}

func BenchmarkRuleEvaluateGround(b *testing.B) {
	silenceBenchmarkLogs(b)
	value := term.NewVariable("value")
	state := rule.NewFact("BenchmarkGroundState", []term.Term{value}, rule.LinearFact)
	r := triggerRule(
		"BenchmarkGround",
		[]*rule.Fact{state, state, state},
		[]*rule.Fact{state, state, state},
		[]*rule.Fact{rule.NewFact("BenchmarkGroundAction", []term.Term{value}, rule.LinearFact)},
		eventTerm("benchmarkGroundOne", value),
		eventTerm("benchmarkGroundTwo", value),
		eventTerm("benchmarkGroundThree", value),
	)
	binding := term.NewBinding()
	binding.Set(value, term.NewConstant[int64](42))

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		evaluated, err := r.EvaluateGround(binding)
		if err != nil || evaluated == nil {
			b.Fatalf("EvaluateGround: %v", err)
		}
	}
}

func BenchmarkFindPossibleEvents(b *testing.B) {
	const ruleCount = 32

	silenceBenchmarkLogs(b)
	value := term.NewVariable("value")
	rules := make([]*rule.Rule, 0, ruleCount)
	for i := range ruleCount {
		name := "BenchmarkPossible" + strconv.Itoa(i)
		state := rule.NewFact(name+"State", []term.Term{value}, rule.LinearFact)
		rhs := make([]*rule.Fact, 16)
		for j := range rhs {
			rhs[j] = rule.NewFact(name+"RHS"+strconv.Itoa(j), []term.Term{value}, rule.LinearFact)
		}
		r := triggerRule(name, []*rule.Fact{state}, rhs, nil, eventTerm(name+"Trigger", value))
		r.Attrs[rule.HintAttributeName] = rule.TermAttribute{
			Value: []term.Term{eventTerm(name+"Hint", value)},
		}
		rules = append(rules, r)
	}
	mon, err := NewMonitor(rules)
	if err != nil {
		b.Fatalf("NewMonitor: %v", err)
	}
	for i := range ruleCount {
		name := "BenchmarkPossible" + strconv.Itoa(i)
		mon.Configs()[0].AddFact(rule.NewFact(
			name+"State",
			[]term.Term{term.NewConstant(int64(i))},
			rule.LinearFact,
		))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if events := mon.findPossibleEvents(); len(events) != 1 || len(events[0]) != 2*ruleCount {
			b.Fatalf("findPossibleEvents returned %d configurations", len(events))
		}
	}
}

func BenchmarkMultiTriggerCandidateBranches(b *testing.B) {
	const (
		candidateCount    = 128
		candidateFactName = "BenchmarkMultiCandidate"
		startEventName    = "benchmarkMultiStart"
		finishEventName   = "benchmarkMultiFinish"
	)

	silenceBenchmarkLogs(b)
	value := term.NewVariable("value")
	unit := term.NewFunction(term.PairFunctionName, nil)
	start := eventTerm(startEventName, unit)
	r := triggerRule(
		"BenchmarkMulti",
		[]*rule.Fact{rule.NewFact(candidateFactName, []term.Term{value}, rule.LinearFact)},
		nil,
		nil,
		start,
		eventTerm(finishEventName, value),
	)
	var pendingBranches int
	b.ReportAllocs()
	for range b.N {
		b.StopTimer()
		mon, err := NewMonitor([]*rule.Rule{r})
		if err != nil {
			b.Fatalf("NewMonitor: %v", err)
		}
		config := mon.Configs()[0]
		for i := range candidateCount {
			config.AddFact(rule.NewFact(candidateFactName, []term.Term{term.NewConstant(int64(i))}, rule.LinearFact))
		}
		b.StartTimer()
		if _, err := mon.ProcessEvent(start); err != nil {
			b.Fatalf("ProcessEvent: %v", err)
		}
		b.StopTimer()
		pendingBranches += len(mon.Configs())
	}
	b.ReportMetric(float64(candidateCount), "candidates/op")
	b.ReportMetric(float64(pendingBranches)/float64(b.N), "pending-branches/op")
}

func silenceBenchmarkLogs(b *testing.B) {
	b.Helper()
	level := log.GetLevel()
	log.SetLevel(log.WarnLevel)
	b.Cleanup(func() { log.SetLevel(level) })
}
