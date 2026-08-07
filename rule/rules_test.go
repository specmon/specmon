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

package rule_test

import (
	"testing"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// Rule.Clone documents that LHS/Act/RHS slice headers and Attrs map are
// independent of the original, while facts and terms inside are shared.
// These tests pin both halves of that contract.
func TestRuleCloneSliceHeadersAreIndependent(t *testing.T) {
	t.Parallel()

	fact := rule.NewFact("F", []term.Term{term.NewVariable("x")}, rule.LinearFact)
	original := &rule.Rule{
		Name:  "R",
		LHS:   []*rule.Fact{fact},
		Act:   []*rule.Fact{fact},
		RHS:   []*rule.Fact{fact},
		Attrs: map[string]rule.Attribute{},
	}

	clone := original.Clone()

	// Mutating the clone's slice headers must not touch the original.
	clone.LHS = append(clone.LHS, rule.NewFact("G", nil, rule.LinearFact))
	if len(original.LHS) != 1 {
		t.Errorf("appending to clone.LHS leaked into original.LHS (size %d, want 1)", len(original.LHS))
	}
}

func TestRuleCloneAttrsMapIsIndependent(t *testing.T) {
	t.Parallel()

	original := &rule.Rule{
		Name: "R",
		Attrs: map[string]rule.Attribute{
			"comment": rule.StringAttribute{Value: "first"},
		},
	}

	clone := original.Clone()

	clone.Attrs["comment"] = rule.StringAttribute{Value: "second"}
	if got := original.Attrs["comment"].(rule.StringAttribute).Value; got != "first" {
		t.Errorf("clone.Attrs write leaked into original (got %q, want %q)", got, "first")
	}
}

func TestRuleCloneTermAttributeSliceIsIndependent(t *testing.T) {
	t.Parallel()

	original := &rule.Rule{
		Name: "R",
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{
				Value: []term.Term{term.NewVariable("x"), term.NewVariable("y")},
			},
		},
	}

	clone := original.Clone()

	cloneAttr := clone.Attrs[rule.TriggerAttributeName].(rule.TermAttribute)
	cloneAttr.Value[0] = term.NewVariable("z")

	origAttr := original.Attrs[rule.TriggerAttributeName].(rule.TermAttribute)
	if got := origAttr.Value[0].(*term.Variable).Name; got != "x" {
		t.Errorf("mutating clone TermAttribute slice element leaked into original (got %q, want %q)", got, "x")
	}
}

func TestRuleCloneSharesFactPointers(t *testing.T) {
	t.Parallel()

	// Document the shallow-fact-sharing contract so the test fails
	// loudly if a future refactor switches to deep-copying facts.
	fact := rule.NewFact("F", []term.Term{term.NewVariable("x")}, rule.LinearFact)
	original := &rule.Rule{
		Name: "R",
		LHS:  []*rule.Fact{fact},
	}

	clone := original.Clone()

	if clone.LHS[0] != original.LHS[0] {
		t.Error("Clone deep-copied fact pointer; the API contract is shallow-fact-sharing")
	}
}

func TestRuleCloneNilRule(t *testing.T) {
	t.Parallel()

	var r *rule.Rule
	if got := r.Clone(); got != nil {
		t.Errorf("nil.Clone() = %v; want nil", got)
	}
}

func TestRuleCloneNilAttrsBecomesEmpty(t *testing.T) {
	t.Parallel()

	original := &rule.Rule{Name: "R", Attrs: nil}

	clone := original.Clone()

	if clone.Attrs == nil {
		t.Fatal("Clone of rule with nil Attrs returned nil Attrs; expected non-nil empty map")
	}
	if len(clone.Attrs) != 0 {
		t.Errorf("Clone of rule with nil Attrs returned non-empty map: %v", clone.Attrs)
	}

	// Caller must be able to assign into the clone's Attrs.
	clone.Attrs["x"] = rule.StringAttribute{Value: "y"}
	if _, ok := original.Attrs["x"]; ok {
		t.Error("assigning to clone.Attrs leaked into original Attrs (which was nil)")
	}
}

func TestRulesDropUnusedRHSFacts(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")
	trigger := term.NewFunction("trigger", []term.Term{x})

	rules := rule.Rules{
		{
			Name: "R1",
			LHS: []*rule.Fact{
				rule.NewFact("State", []term.Term{x}, rule.LinearFact),
				rule.NewFact("Live", []term.Term{x}, rule.LinearFact),
			},
			Act: []*rule.Fact{
				rule.NewFact("Existing", []term.Term{term.NewConstant("keep")}, rule.LinearFact),
			},
			RHS: []*rule.Fact{
				rule.NewFact("DeadConst", []term.Term{term.NewConstant("a")}, rule.LinearFact),
				rule.NewFact("DeadVar", []term.Term{x}, rule.LinearFact),
				rule.NewFact("Live", []term.Term{x}, rule.LinearFact),
				rule.NewFact("Live", []term.Term{x, y}, rule.LinearFact),
			},
			Attrs: map[string]rule.Attribute{
				rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{trigger}},
			},
		},
	}
	original := rules[0].String()

	got := rules.DropUnusedRHSFacts()

	if rules[0].String() != original {
		t.Fatalf("expected original rule to stay unchanged:\nwant: %s\ngot:  %s", original, rules[0])
	}
	if got[0] == rules[0] {
		t.Fatal("expected the transformation to clone the selected rule")
	}
	if len(got[0].RHS) != 1 || got[0].RHS[0].Name != "Live" {
		t.Fatalf("unexpected rewritten RHS: %#v", got[0].RHS)
	}
	if len(got[0].RHS[0].Args) != 1 {
		t.Fatalf("same-name RHS fact with a different arity was retained: %#v", got[0].RHS)
	}
	if len(got[0].Act) != 1 || got[0].Act[0].Name != "Existing" {
		t.Fatalf("constant-only or variable-only facts changed actions: %#v", got[0].Act)
	}
	if len(got[0].LHS) != len(rules[0].LHS) {
		t.Fatalf("expected LHS facts to be preserved, got %#v", got[0].LHS)
	}
	if !got[0].Triggers()[0].Equal(trigger) {
		t.Fatalf("expected trigger attribute to be preserved, got %#v", got[0].Attrs)
	}
}

func TestRulesDropUnusedRHSFactsPreservesComputations(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")
	hx := term.NewFunction("h", []term.Term{x})
	equivalentHX := term.NewFunction("h", []term.Term{term.NewVariable("x")})
	gx := term.NewFunction("g", []term.Term{x})
	equivalentGX := term.NewFunction("g", []term.Term{term.NewVariable("x")})
	ky := term.NewFunction("k", []term.Term{y})

	existingAction := rule.NewFact("Existing", nil, rule.LinearFact)
	internalAction := rule.NewFact(rule.ComputeFactName, []term.Term{ky}, rule.LinearFact)
	rules := rule.Rules{
		{
			Name: "R",
			LHS: []*rule.Fact{
				rule.NewFact("State", []term.Term{x}, rule.LinearFact),
				rule.NewFact("Live", []term.Term{x}, rule.LinearFact),
			},
			Act: []*rule.Fact{existingAction, internalAction},
			RHS: []*rule.Fact{
				rule.NewFact("Dead", []term.Term{hx, gx}, rule.LinearFact),
				rule.NewFact("Live", []term.Term{x}, rule.LinearFact),
				rule.NewFact(rule.ComputeFactName, []term.Term{equivalentHX}, rule.LinearFact),
				rule.NewFact("AlsoDead", []term.Term{equivalentGX, ky, gx}, rule.LinearFact),
			},
			Attrs: map[string]rule.Attribute{},
		},
	}

	got := rules.DropUnusedRHSFacts()

	if len(got[0].Act) != 2 || got[0].Act[0] != existingAction || got[0].Act[1] != internalAction {
		t.Fatalf("existing action order changed: %#v", got[0].Act)
	}
	if len(got[0].RHS) != 4 {
		t.Fatalf("expected generated, live, existing, and generated RHS facts, got %#v", got[0].RHS)
	}

	wantNames := []string{rule.ComputeFactName, "Live", rule.ComputeFactName, rule.ComputeFactName}
	for i, want := range wantNames {
		if got[0].RHS[i].Name != want {
			t.Fatalf("RHS fact %d: expected %s, got %s", i, want, got[0].RHS[i].Name)
		}
	}
	wantComputed := []term.Term{gx, equivalentHX, ky}
	for i, rhsIndex := range []int{0, 2, 3} {
		if !got[0].RHS[rhsIndex].Args[0].Equal(wantComputed[i]) {
			t.Fatalf("computation %d: expected %s, got %s", i, wantComputed[i], got[0].RHS[rhsIndex].Args[0])
		}
	}
}

func TestRulesDropUnusedRHSFactsPreservesApplicabilityAndActions(t *testing.T) {
	x := term.NewVariable("x")
	value := term.NewConstant(2)
	computed := term.NewFunction(term.AddFunctionName, []term.Term{x, term.NewConstant(1)})

	producer := &rule.Rule{
		Name: "Producer",
		LHS:  []*rule.Fact{rule.NewFact("State", []term.Term{x}, rule.LinearFact)},
		Act:  []*rule.Fact{rule.NewFact("Existing", []term.Term{x}, rule.LinearFact)},
		RHS: []*rule.Fact{
			rule.NewFact("Next", []term.Term{x}, rule.LinearFact),
			rule.NewFact("Dead", []term.Term{computed}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{},
	}
	consumer := &rule.Rule{
		Name:  "Consumer",
		LHS:   []*rule.Fact{rule.NewFact("Next", []term.Term{x}, rule.LinearFact)},
		RHS:   []*rule.Fact{rule.NewFact("Done", []term.Term{x}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{},
	}
	rewritten := rule.Rules{producer, consumer}.DropUnusedRHSFacts()[0]

	binding := term.NewBinding()
	binding.Set(x, value)
	originalConfig := monitor.NewConfig()
	originalConfig.AddFact(rule.NewFact("State", []term.Term{value}, rule.LinearFact))
	filteredConfig := monitor.NewConfig()
	filteredConfig.AddFact(rule.NewFact("State", []term.Term{value}, rule.LinearFact))

	originalResult, originalActions, err := originalConfig.ApplyRule(producer, binding)
	if err != nil {
		t.Fatalf("applying original producer: %v", err)
	}
	filteredResult, filteredActions, err := filteredConfig.ApplyRule(rewritten, binding)
	if err != nil {
		t.Fatalf("applying rewritten producer: %v", err)
	}

	if originalResult.CountByName("Next") != 1 || filteredResult.CountByName("Next") != 1 {
		t.Fatal("rewriting changed the live fact needed by the consumer")
	}
	if originalResult.CountByName("Dead") != 1 || filteredResult.CountByName("Dead") != 0 {
		t.Fatal("rewritten result did not omit only the dead fact")
	}
	if filteredResult.CountByName(rule.ComputeFactName) != 0 {
		t.Fatal("internal computation fact entered the configuration")
	}
	if len(originalActions) != 1 || len(filteredActions) != 1 || !originalActions[0].Equal(filteredActions[0]) {
		t.Fatalf("rewriting changed actions: original=%v filtered=%v", originalActions, filteredActions)
	}
	if filteredActions[0].Name == rule.ComputeFactName {
		t.Fatal("internal computation fact was returned as an action")
	}

	if _, _, err := originalResult.ApplyRule(consumer, binding); err != nil {
		t.Fatalf("consumer no longer applies to original result: %v", err)
	}
	if _, _, err := filteredResult.ApplyRule(consumer, binding); err != nil {
		t.Fatalf("consumer no longer applies to rewritten result: %v", err)
	}
}

func TestIsInternalFactName(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{name: rule.ComputeFactName, want: true},
		{name: "Scratch_", want: true},
		{name: "Public", want: false},
		{name: "_Leading", want: false},
	} {
		if got := rule.IsInternalFactName(test.name); got != test.want {
			t.Errorf("IsInternalFactName(%q) = %t, want %t", test.name, got, test.want)
		}
	}
}
