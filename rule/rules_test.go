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
	"errors"
	"fmt"
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

var benchmarkRuleSubstSink *rule.Rule

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

// Dead and AlsoDead are consumed by no rule, so each of their function
// arguments stays once as a Compute_ fact; h(x) already is one. Consumer
// consumes Next(x) but not Next(x, x), which has another arity.
func TestRulesDropUnusedRHSFacts(t *testing.T) {
	x := term.NewVariable("x")
	hx := term.NewFunction("h", []term.Term{x})
	gx := term.NewFunction("g", []term.Term{x})
	fact := func(name string, args ...term.Term) *rule.Fact {
		return rule.NewFact(name, args, rule.LinearFact)
	}
	producer := &rule.Rule{
		Name: "Producer",
		LHS:  []*rule.Fact{fact("State", x)},
		Act:  []*rule.Fact{fact(rule.ComputeFactName, gx)},
		RHS: []*rule.Fact{
			fact("Dead", term.NewConstant("a"), x, hx, gx),
			fact("Next", x),
			fact("Next", x, x),
			fact(rule.ComputeFactName, term.NewFunction("h", []term.Term{term.NewVariable("x")})),
			fact("AlsoDead", term.NewFunction("g", []term.Term{x}), term.NewFunction("k", []term.Term{x})),
		},
		Attrs: map[string]rule.Attribute{rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{hx}}},
	}
	consumer := &rule.Rule{Name: "Consumer", LHS: []*rule.Fact{fact("Next", x)}, Attrs: map[string]rule.Attribute{}}
	original := producer.String()

	got := rule.Rules{producer, consumer}.DropUnusedRHSFacts()

	if producer.String() != original {
		t.Fatalf("original rule changed:\n%s", producer)
	}
	want := "[Compute_(g(x)) Next(x) Compute_(h(x)) Compute_(k(x))]"
	if rhs := fmt.Sprint(got[0].RHS); rhs != want {
		t.Fatalf("RHS = %s, want %s", rhs, want)
	}
	got[0].RHS = producer.RHS
	if got[0].String() != original || got[1].String() != consumer.String() {
		t.Fatalf("rules changed outside the RHS:\n%s\n%s", got[0], got[1])
	}
}

func TestFactUnifyPreservesEvaluationErrors(t *testing.T) {
	t.Parallel()

	invalid := term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant[int64](1)})
	left := rule.NewFact("Evaluated", []term.Term{invalid}, rule.LinearFact)
	right := rule.NewFact("Evaluated", []term.Term{term.NewConstant[int64](1)}, rule.LinearFact)

	_, err := left.Unify(right)
	if !errors.Is(err, rule.ErrFactUnify) {
		t.Fatalf("Fact.Unify error = %v, want ErrFactUnify", err)
	}
	if !errors.Is(err, term.ErrEvaluation) {
		t.Fatalf("Fact.Unify error = %v, want wrapped ErrEvaluation", err)
	}
	if !errors.Is(err, term.ErrBinaryArity) {
		t.Fatalf("Fact.Unify error = %v, want wrapped ErrBinaryArity", err)
	}
}

func TestEvaluateGroundKeepsRewriteOutputCall(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	inner := term.NewFunction("inner", []term.Term{x})
	outer := term.NewFunction("output", []term.Term{inner, x})
	result := term.NewFunction(term.AddFunctionName, []term.Term{outer, inner})
	output := rule.NewFact(rule.RewriteEventName, []term.Term{
		term.NewFunction(term.PairFunctionName, []term.Term{outer, result}),
	}, rule.LinearFact)
	r := &rule.Rule{
		Name: "RewriteOutput",
		Act: []*rule.Fact{
			output,
			rule.NewFact("Observed", []term.Term{outer, inner}, rule.LinearFact),
		},
		RHS: []*rule.Fact{rule.NewFact("Done", []term.Term{outer, inner}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{
				term.NewFunction(term.PairFunctionName, []term.Term{outer, term.NewConstant[int64](7)}),
				term.NewFunction(term.PairFunctionName, []term.Term{inner, term.NewConstant[int64](2)}),
			}},
		},
	}
	original := r.String()
	binding := term.BindingFromMap(map[term.Term]term.Term{x: term.NewConstant("input")})

	evaluated, err := r.EvaluateGround(binding)
	if err != nil {
		t.Fatal(err)
	}
	wantOutput := rule.NewFact(rule.RewriteEventName, []term.Term{
		term.NewFunction(term.PairFunctionName, []term.Term{
			term.NewFunction("output", []term.Term{term.NewConstant[int64](2), term.NewConstant("input")}),
			term.NewConstant[int64](9),
		}),
	}, rule.LinearFact)
	if !evaluated.Act[0].Equal(wantOutput) {
		t.Fatalf("rewrite action = %s, want %s", evaluated.Act[0], wantOutput)
	}
	wantObserved := rule.NewFact("Observed", []term.Term{
		term.NewConstant[int64](7), term.NewConstant[int64](2),
	}, rule.LinearFact)
	if !evaluated.Act[1].Equal(wantObserved) {
		t.Fatalf("ordinary action = %s, want %s", evaluated.Act[1], wantObserved)
	}
	wantDone := rule.NewFact("Done", wantObserved.Args, rule.LinearFact)
	if !evaluated.RHS[0].Equal(wantDone) {
		t.Fatalf("conclusion = %s, want %s", evaluated.RHS[0], wantDone)
	}
	if r.String() != original {
		t.Fatalf("EvaluateGround mutated the input rule:\n%s", r)
	}
}

func BenchmarkRuleSubst(b *testing.B) {
	value := term.NewVariable("value")
	fact := rule.NewFact("BenchmarkSubst", []term.Term{value}, rule.LinearFact)
	r := &rule.Rule{
		Name: "BenchmarkSubst",
		LHS:  []*rule.Fact{fact, fact, fact},
		Act:  []*rule.Fact{fact},
		RHS:  []*rule.Fact{fact, fact, fact},
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{value, value, value}},
			rule.HintAttributeName:    rule.TermAttribute{Value: []term.Term{value, value, value}},
		},
	}
	binding := term.NewBinding()
	binding.Set(value, term.NewConstant[int64](42))

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		benchmarkRuleSubstSink = r.Subst(binding)
	}
}

func BenchmarkRuleReplaceFormats(b *testing.B) {
	value := term.NewConstant[int64](42)
	fact := rule.NewFact("BenchmarkReplaceFormats", []term.Term{value}, rule.LinearFact)
	r := &rule.Rule{
		Name: "BenchmarkReplaceFormats",
		LHS:  []*rule.Fact{fact, fact, fact},
		Act:  []*rule.Fact{fact},
		RHS:  []*rule.Fact{fact, fact, fact},
		Attrs: map[string]rule.Attribute{
			rule.TriggerAttributeName: rule.TermAttribute{Value: []term.Term{value, value, value}},
			rule.HintAttributeName:    rule.TermAttribute{Value: []term.Term{value, value, value}},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		replaced, err := r.ReplaceFormats()
		if err != nil {
			b.Fatalf("ReplaceFormats: %v", err)
		}
		benchmarkRuleSubstSink = replaced
	}
}

func TestMacroSubstitutionBeforeUnification(t *testing.T) {
	parameter := term.NewVariable("x")
	head := term.NewFunction("m", []term.Term{parameter})
	body := term.NewFunction("cat", []term.Term{term.NewFunction("byte", []term.Term{parameter})})
	macros := term.NewBinding()
	macros.Set(head, body)
	application := term.NewFunction("m", []term.Term{term.NewFunction("h", []term.Term{term.NewVariable("x")})})
	facts := rule.Facts{rule.NewFact("Next", []term.Term{application}, rule.LinearFact)}
	got := facts.ExpandFacts(macros)[0].Args[0].String()
	t.Logf("expanded = %s", got)
	if got != "cat(byte(h(x)))" {
		t.Fatalf("macro did not substitute its parameter: %s", got)
	}
}

func TestExpandFormatsDoesNotMutateAnnotations(t *testing.T) {
	x := term.NewVariable("x")
	call := term.NewFunction("m", []term.Term{x})
	macros := term.NewBinding()
	macros.Set(call, term.NewFunction("h", []term.Term{x}))
	shared := []term.Term{call}
	original := rule.NewRule()
	original.Attrs[rule.TriggerAttributeName] = rule.TermAttribute{Value: shared}
	original.Attrs[rule.HintAttributeName] = rule.TermAttribute{Value: shared}
	expanded := original.ExpandFormats(macros)
	for _, name := range []string{rule.TriggerAttributeName, rule.HintAttributeName} {
		if got := expanded.Attrs[name].GetTerms()[0].String(); got != "h(x)" {
			t.Fatalf("expanded %s = %s, want h(x)", name, got)
		}
		expanded.Attrs[name].GetTerms()[0] = term.NewVariable("changed")
		if got := original.Attrs[name].GetTerms()[0].String(); got != "m(x)" {
			t.Fatalf("original %s changed to %s", name, got)
		}
	}
	if got := call.String(); got != "m(x)" {
		t.Fatalf("shared term changed to %s", got)
	}
}

func TestFactEqualityKindAndCoercion(t *testing.T) {
	a := term.NewConstant("ab")
	linear := rule.NewFact("State", []term.Term{a}, rule.LinearFact)
	persistent := rule.NewFact("State", []term.Term{a}, rule.PersistentFact)
	if linear.Equal(persistent) || persistent.Equal(linear) {
		t.Error("Fact.Equal ignores persistence kind")
	}
	integer := term.NewConstant[int64](1)
	encoded, err := term.AsBytes(integer)
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range [][2]term.Term{
		{a, term.NewConstant([]byte("ab"))},
		{integer, term.NewConstant(encoded)},
		{term.NewFunction("f", []term.Term{a}), term.NewFunction("f", []term.Term{term.NewConstant([]byte("ab"))})},
	} {
		for _, kind := range []rule.FactType{rule.LinearFact, rule.PersistentFact} {
			left := rule.NewFact("State", []term.Term{values[0]}, kind)
			right := rule.NewFact("State", []term.Term{values[1]}, kind)
			if !left.Equal(right) || !right.Equal(left) || left.Hash() != right.Hash() {
				t.Fatalf("kind-only fix changed constant equality/hash: %v,%v", left, right)
			}
		}
	}
}
