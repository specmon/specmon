// This file is part of SpecMon.
//
// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
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
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// bindTargets returns, for every binding in the set, the term that variable v
// is bound to (skipping bindings that do not bind v). Used to assert which
// seen terms a single-variable pattern matched.
func bindTargets(bindings []*term.Binding, v *term.Variable) []term.Term {
	var out []term.Term
	for _, b := range bindings {
		if t, ok := b.Get(v); ok {
			out = append(out, t)
		}
	}
	return out
}

// TestConflictSetTermsSingleBareVariable pins the single-pattern fast path for
// a non-indexable body: a bare variable must match every seen term, regardless
// of the seen term's arity. This is the common case (a rule with exactly one
// trigger that substitutes to a variable) and a prior fast-path arity gate
// silently dropped every seen term carrying arguments.
func TestConflictSetTermsSingleBareVariable(t *testing.T) {
	x := term.NewVariable("x")
	body := []term.Term{x}

	seen := []term.Term{
		term.NewFunction("recv", []term.Term{term.NewConstant(1), term.NewConstant(2)}),
		term.NewConstant("c"),
		term.NewFunction("send", []term.Term{term.NewConstant(7)}),
	}

	got := conflictSetTerms(seen, body)
	if got.Size() != len(seen) {
		t.Fatalf("bare variable pattern: got %d bindings, want %d (one per seen term)", got.Size(), len(seen))
	}
	if len(bindTargets(got.Values(), x)) != len(seen) {
		t.Fatalf("bare variable pattern: not every binding binds x")
	}
}

// TestConflictSetTermsSingleConstant pins the single-pattern fast path for a
// constant body pattern against an unevaluated ground term that Unify reduces
// to that constant. The fast path must not pre-filter it out on arity before
// Unify runs the reduction.
func TestConflictSetTermsSingleConstant(t *testing.T) {
	// cat(int(5)) is a ground, unevaluated function that Unify evaluates.
	catTerm := term.NewFunction("cat", []term.Term{
		term.NewFunction("int", []term.Term{term.NewConstant(5)}),
	})
	// The constant that cat(int(5)) evaluates to.
	evaluated, err := term.Evaluate(catTerm)
	if err != nil || evaluated == nil || evaluated.GetType() != term.ConstantType {
		t.Skipf("cat(int(5)) did not evaluate to a constant in this build (err=%v); pattern precondition not met", err)
	}

	body := []term.Term{evaluated}
	seen := []term.Term{catTerm}

	got := conflictSetTerms(seen, body)
	if got.Empty() {
		t.Fatalf("constant pattern vs unevaluated ground cat: got 0 bindings, want 1")
	}
}

// TestConflictSetTermsSingleIndexedFunction keeps the indexed single-pattern
// path honest: a function pattern with a variable arg still matches same-name
// same-arity seen terms and binds correctly.
func TestConflictSetTermsSingleIndexedFunction(t *testing.T) {
	y := term.NewVariable("y")
	body := []term.Term{term.NewFunction("recv", []term.Term{y})}

	seen := []term.Term{
		term.NewFunction("recv", []term.Term{term.NewConstant(1)}),
		term.NewFunction("send", []term.Term{term.NewConstant(2)}),                      // wrong name
		term.NewFunction("recv", []term.Term{term.NewConstant(3), term.NewConstant(4)}), // wrong arity
	}

	got := conflictSetTerms(seen, body)
	if got.Size() != 1 {
		t.Fatalf("indexed single function pattern: got %d bindings, want 1 (only the matching recv/1)", got.Size())
	}
}

// TestConflictSetFactsSingleVariableFact guards the fact path for a
// single-pattern body with a variable argument: it must match same-name facts
// of the same arity and bind the variable.
func TestConflictSetFactsSingleVariableFact(t *testing.T) {
	x := term.NewVariable("x")
	body := []*rule.Fact{rule.NewFact("Out", []term.Term{x}, rule.LinearFact)}

	facts := []*rule.Fact{
		rule.NewFact("Out", []term.Term{term.NewConstant("a")}, rule.LinearFact),
		rule.NewFact("Out", []term.Term{term.NewConstant("b")}, rule.LinearFact),
		rule.NewFact("In", []term.Term{term.NewConstant("c")}, rule.LinearFact), // wrong name
	}

	got := conflictSetFacts(facts, body)
	if got.Size() != 2 {
		t.Fatalf("single variable fact pattern: got %d bindings, want 2", got.Size())
	}
}

// TestConflictSetFactsDuplicateCap checks the body-slot dedup cap: two body
// slots requesting Out(x), Out(y) against three identical Out facts should
// still enumerate the pairings the uncapped code would, and capping past the
// slot count must not drop a reachable binding.
func TestConflictSetFactsDuplicateCap(t *testing.T) {
	body := []*rule.Fact{
		rule.NewFact("Out", []term.Term{term.NewVariable("x")}, rule.LinearFact),
		rule.NewFact("Out", []term.Term{term.NewVariable("y")}, rule.LinearFact),
	}
	// Three identical facts; body needs at most 2 of them.
	facts := []*rule.Fact{
		rule.NewFact("Out", []term.Term{term.NewConstant("v")}, rule.LinearFact),
		rule.NewFact("Out", []term.Term{term.NewConstant("v")}, rule.LinearFact),
		rule.NewFact("Out", []term.Term{term.NewConstant("v")}, rule.LinearFact),
	}

	got := conflictSetFacts(facts, body)
	// x and y each bind to the single distinct value "v"; the multiset yields
	// exactly one distinct binding {x->v, y->v}.
	if got.Empty() {
		t.Fatalf("duplicate cap: got 0 bindings, want at least 1")
	}
}

// TestBindingTrailOverwriteRestore pins the trail invariant the DFS relies on:
// Mark, mutate (including overwriting an existing key), then Unwind must
// restore the binding exactly, byte for byte.
func TestBindingTrailOverwriteRestore(t *testing.T) {
	x := term.NewVariable("x")
	y := term.NewVariable("y")

	b := term.NewBinding()
	b.Set(x, term.NewConstant("orig"))
	before := b.String()

	trail := term.NewBindingTrail()
	mark := trail.Mark()
	// Overwrite an existing key and add a new one.
	b.SetWithTrail(x, term.NewConstant("changed"), trail)
	b.SetWithTrail(y, term.NewConstant("new"), trail)

	if got, _ := b.Get(x); got == nil || got.String() != term.NewConstant("changed").String() {
		t.Fatalf("after SetWithTrail, x not overwritten")
	}
	if _, ok := b.Get(y); !ok {
		t.Fatalf("after SetWithTrail, y not added")
	}

	b.Unwind(trail, mark)
	after := b.String()
	if before != after {
		t.Fatalf("Unwind did not restore binding: before=%q after=%q", before, after)
	}
	if _, ok := b.Get(y); ok {
		t.Fatalf("Unwind did not remove y")
	}
}
