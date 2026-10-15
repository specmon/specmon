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

package rule_test

import (
	"fmt"
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
	"github.com/stretchr/testify/require"
)

func TestIsStartRuleOf(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		r1, r2 string
		want   bool
	}{
		{"R_Start", "R_0", true},
		{"R_Start", "R_End", true},
		{"R_NotStart", "R_0_1", false},
		{"R_Start", "Q_0", false},
		{"R_Start", "R_Start", true},
		{"R_Start", "R_Q_End", false},
		{"R_Start", "R_Q_0", false},
		{"R_Start", "R_+1", false},
		{"R_Start", "R_00", false},
	} {
		if got := rule.IsStartRuleOf(&rule.Rule{Name: test.r1}, &rule.Rule{Name: test.r2}); got != test.want {
			t.Errorf("IsStartRuleOf(%s, %s) = %v, want %v", test.r1, test.r2, got, test.want)
		}
	}
}

func TestTranslateKeepsReservedEvaluatorsInline(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	for _, operation := range []*term.Function{
		term.NewFunction(term.XorFunctionName, []term.Term{x, term.NewConstant[int64](1)}),
		term.NewFunction(term.NotFunctionName, []term.Term{x}),
		term.NewFunction(term.ReverseFuncName, []term.Term{x}),
	} {
		t.Run(operation.Name, func(t *testing.T) {
			t.Parallel()
			original := &rule.Rule{
				Name: "ReservedEvaluator",
				RHS: []*rule.Fact{
					rule.NewFact("Result", []term.Term{operation}, rule.LinearFact),
				},
				Attrs: map[string]rule.Attribute{},
			}

			got := rule.Translate(original)
			if len(got) != 1 {
				t.Fatalf("Translate returned %d rules, want one", len(got))
			}
			if !got[0].RHS[0].Args[0].Equal(operation) {
				t.Fatalf("Translate decomposed reserved evaluator %s: %v", operation.Name, got)
			}
		})
	}
}

// TestTranslateInputImmutability verifies that Translate never mutates
// the input rule's RHS, Act, or Attrs, and that the end rule replaces the
// computations of both by their result variables.
func TestTranslateInputImmutability(t *testing.T) {
	t.Parallel()

	m := term.NewVariable("m")
	hashM := term.NewFunction("hash", []term.Term{m})
	lenHashM := term.NewFunction("len", []term.Term{hashM})

	r := &rule.Rule{
		Name: "R",
		LHS:  []*rule.Fact{rule.NewFact("In", []term.Term{m}, rule.LinearFact)},
		Act:  []*rule.Fact{rule.NewFact("Act", []term.Term{lenHashM}, rule.LinearFact)},
		RHS:  []*rule.Fact{rule.NewFact("Out", []term.Term{lenHashM}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			"custom": rule.StringAttribute{Value: "test"},
		},
	}

	// Snapshot string representations before translation.
	rhsBefore := fmt.Sprint(r.RHS)
	actBefore := fmt.Sprint(r.Act)
	attrsBefore := fmt.Sprint(r.Attrs)

	rules := rule.Translate(r)

	require.Equal(t, rhsBefore, fmt.Sprint(r.RHS), "Translate mutated input RHS")
	require.Equal(t, actBefore, fmt.Sprint(r.Act), "Translate mutated input Act")
	require.Equal(t, attrsBefore, fmt.Sprint(r.Attrs), "Translate mutated input Attrs")
	end := rules[len(rules)-1]
	require.Equal(t, "[Out(l_h_m)]", fmt.Sprint(end.RHS), "end rule conclusions")
	require.Equal(t, "[Act(l_h_m)]", fmt.Sprint(end.Act), "end rule actions")
}

// TestTranslateKeepsPremiseOrder checks that the start rule and the fused
// rule of a single innermost computation, which match the premises of the
// source rule, leave the order of those premises unchanged.
func TestTranslateKeepsPremiseOrder(t *testing.T) {
	t.Parallel()

	m := term.NewVariable("m")
	hashM := term.NewFunction("hash", []term.Term{m})
	for name, out := range map[string]term.Term{
		"start rule":      term.NewFunction("len", []term.Term{hashM, term.NewFunction("size", []term.Term{m})}),
		"fused leaf rule": term.NewFunction("len", []term.Term{hashM}),
	} {
		r := &rule.Rule{
			Name: "R",
			LHS: []*rule.Fact{
				rule.NewFact("State", []term.Term{m}, rule.LinearFact),
				rule.NewFact("In", []term.Term{m}, rule.LinearFact),
			},
			RHS:   []*rule.Fact{rule.NewFact("Out", []term.Term{out}, rule.LinearFact)},
			Attrs: map[string]rule.Attribute{},
		}
		rule.Translate(r)
		require.Equal(t, "[State(m) In(m)]", fmt.Sprint(r.LHS), name)
	}
}
