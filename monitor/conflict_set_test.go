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
	"math"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

func TestFormatFieldLengthChecksStructuralBounds(t *testing.T) {
	t.Parallel()

	field := term.NewFunction(string(term.FormatIntType), []term.Term{
		term.NewVariable("x"),
		term.NewConstant[int64](math.MaxInt64),
	})
	length, known, variable := formatFieldLength(field)
	if strconv.IntSize == 32 {
		if known || variable {
			t.Fatalf("32-bit structural length accepted: %d", length)
		}
	} else if !known || variable || int64(length) != math.MaxInt64 {
		t.Fatalf("64-bit structural length = %d, %t, %t", length, known, variable)
	}

	cat := term.NewFunction(term.CatFunctionName, []term.Term{field, field})
	if _, ok := formatConstraintForCat(cat); ok {
		t.Fatal("combined field lengths overflowed the structural total")
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

const (
	prefilterTestFactA    = "PrefilterA"
	prefilterTestFactB    = "PrefilterB"
	prefilterTestFunction = "prefilterF"
)

// prefilterTestConstants mixes constant kinds, including an int64 and a byte
// string of the same width, so that equal-looking values of different kinds
// meet in one bucket.
var prefilterTestConstants = []term.Term{
	term.NewConstant[int64](1),
	term.NewConstant[int64](2),
	term.NewConstant("a"),
	term.NewConstant("b"),
	term.NewConstant([]byte{0x01}),
	term.NewConstant([]byte{0x02}),
	term.NewConstant([]byte{0, 0, 0, 0, 0, 0, 0, 1}),
	term.NewConstant([]byte{0x01, 0x02, 0x03}),
}

func randomPrefilterFactArg(r *rand.Rand) term.Term {
	constant := prefilterTestConstants[r.IntN(len(prefilterTestConstants))]
	if r.IntN(6) == 0 {
		return term.NewFunction(prefilterTestFunction, []term.Term{constant})
	}
	return constant
}

func randomPrefilterPatternArg(r *rand.Rand) term.Term {
	variables := []*term.Variable{term.NewVariable("x"), term.NewVariable("y"), term.NewVariable("z")}
	switch r.IntN(10) {
	case 0, 1, 2, 3:
		return prefilterTestConstants[r.IntN(len(prefilterTestConstants))]
	case 4:
		return term.NewFunction(prefilterTestFunction, []term.Term{variables[r.IntN(len(variables))]})
	case 5:
		return term.NewFunction(term.CatFunctionName, []term.Term{
			term.NewFunction(string(term.FormatByteType), []term.Term{variables[0], term.NewConstant[int64](2)}),
			term.NewFunction(string(term.FormatByteType), []term.Term{variables[1]}),
		})
	default:
		return variables[r.IntN(len(variables))]
	}
}

func randomPrefilterFactType(r *rand.Rand) rule.FactType {
	if r.IntN(2) == 0 {
		return rule.PersistentFact
	}
	return rule.LinearFact
}

func randomPrefilterBucket(r *rand.Rand, name string, size int) []*rule.Fact {
	facts := make([]*rule.Fact, 0, size)
	for len(facts) < size {
		if len(facts) > 0 && r.IntN(5) == 0 {
			// A duplicate, either the same fact or an equal copy.
			previous := facts[r.IntN(len(facts))]
			if r.IntN(2) == 0 {
				facts = append(facts, previous)
			} else {
				facts = append(facts, rule.NewFact(previous.Name, previous.Args, previous.Type))
			}
			continue
		}
		args := make([]term.Term, 1+r.IntN(3))
		for i := range args {
			args[i] = randomPrefilterFactArg(r)
		}
		facts = append(facts, rule.NewFact(name, args, randomPrefilterFactType(r)))
	}
	return facts
}

// TestConflictSetFactsForConfigPrefilterKeepsBindings compares the conflict
// set of a configuration with the conflict set of the unfiltered buckets.
// The bindings and their order must be identical.
func TestConflictSetFactsForConfigPrefilterKeepsBindings(t *testing.T) {
	t.Parallel()

	sizes := []int{0, 1, 5, constCandidateMinBucket - 1, constCandidateMinBucket, constCandidateMinBucket + 1, 64, 200}
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // A fixed seed keeps the comparison reproducible.
	matched, filtered := 0, 0
	for iteration := range 3000 {
		c := NewConfig()
		for _, f := range randomPrefilterBucket(r, prefilterTestFactA, sizes[iteration%len(sizes)]) {
			c.AddFact(f)
		}
		for _, f := range randomPrefilterBucket(r, prefilterTestFactB, sizes[r.IntN(len(sizes))]) {
			c.AddFact(f)
		}

		body := make([]*rule.Fact, 1+r.IntN(3))
		for i := range body {
			name := prefilterTestFactA
			if r.IntN(3) == 0 {
				name = prefilterTestFactB
			}
			args := make([]term.Term, 1+r.IntN(3))
			for j := range args {
				args[j] = randomPrefilterPatternArg(r)
			}
			body[i] = rule.NewFact(name, args, randomPrefilterFactType(r))
		}

		// The unfiltered item list with as many copies of every fact as
		// body has patterns of its name, in the order
		// conflictSetFactsForConfig visits the buckets and their entries.
		var items []*rule.Fact
		visited := map[string]bool{}
		for _, p := range body {
			if !visited[p.Name] {
				visited[p.Name] = true
				bucket := c.factsByName[p.Name]
				slots := 0
				for _, q := range body {
					if q.Name == p.Name {
						slots++
					}
				}
				for _, e := range bucket.entries {
					for range min(e.count, slots) {
						items = append(items, e.fact)
					}
				}
				if kept := appendConstCandidates(nil, bucket, body, p.Name, bucket.total); len(kept) < bucket.total {
					filtered++
				}
			}
		}

		want := conflictSetFacts(items, body).Values()
		if got := conflictSetFactsForConfig(c, body).Values(); !slices.EqualFunc(got, want, (*term.Binding).Equal) {
			t.Fatalf("iteration %d, body %v: bindings %v, want %v", iteration, body, got, want)
		}
		if len(want) > 0 {
			matched++
		}
	}
	// Guard against a vacuous comparison.
	if matched < 100 || filtered < 100 {
		t.Fatalf("only %d iterations matched and %d filtered a bucket", matched, filtered)
	}
}

// BenchmarkConflictSetFactsForConfigLargePersistentBucket matches a rule
// whose persistent premise has a bound constant against a bucket of 3,000
// persistent facts.
func BenchmarkConflictSetFactsForConfigLargePersistentBucket(b *testing.B) {
	const (
		stateFact   = "PrefilterState"
		allowedFact = "PrefilterAllowedTo"
		senders     = 100
		recipients  = 30
	)
	c := NewConfig()
	for s := range senders {
		for r := range recipients {
			c.AddFact(rule.NewFact(allowedFact, []term.Term{
				term.NewConstant("sender" + strconv.Itoa(s)),
				term.NewConstant("recipient" + strconv.Itoa(r)),
			}, rule.PersistentFact))
		}
	}
	c.AddFact(rule.NewFact(stateFact, []term.Term{term.NewConstant("sender7"), term.NewConstant[int64](1)}, rule.LinearFact))
	body := []*rule.Fact{
		rule.NewFact(stateFact, []term.Term{term.NewConstant("sender7"), term.NewVariable("n")}, rule.LinearFact),
		rule.NewFact(allowedFact, []term.Term{term.NewConstant("sender7"), term.NewVariable("r")}, rule.PersistentFact),
	}

	b.ReportAllocs()
	for b.Loop() {
		if got := conflictSetFactsForConfig(c, body).Size(); got != recipients {
			b.Fatalf("bindings = %d, want %d", got, recipients)
		}
	}
}
