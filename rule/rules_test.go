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

package rule_test

import (
	"testing"

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
