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
	"maps"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

const (
	storageTestFact     = "StorageTestFact"
	storageTestDone     = "StorageTestDone"
	storageTestLearn    = "storage_test_learn"
	storageTestUse      = "storage_test_use"
	storageTestConsume  = "storage_test_consume"
	storageTestRuleName = "StorageTestRule"
)

func storagePersistent(args ...term.Term) *rule.Fact {
	return rule.NewFact(storageTestFact, args, rule.PersistentFact)
}

func storageLinear(args ...term.Term) *rule.Fact {
	return rule.NewFact(storageTestFact, args, rule.LinearFact)
}

func TestConfigPersistentFactsFormASet(t *testing.T) {
	t.Parallel()

	a := term.NewConstant("a")
	once := NewConfig()
	once.AddFact(storagePersistent(a))

	twice := NewConfig()
	twice.AddFact(storagePersistent(a))
	twice.AddFact(storagePersistent(a))

	if got := twice.CountByName(storageTestFact); got != 1 {
		t.Fatalf("CountByName after adding a persistent fact twice = %d, want 1", got)
	}
	if got := len(twice.Facts()); got != 1 {
		t.Fatalf("Facts after adding a persistent fact twice = %d facts, want 1", got)
	}
	if once.Hash() != twice.Hash() {
		t.Fatalf("Hash differs after adding a persistent fact again: %d != %d", once.Hash(), twice.Hash())
	}
}

func TestConfigSeparatesFactKinds(t *testing.T) {
	t.Parallel()

	a := term.NewConstant("a")
	c := NewConfig()
	c.AddFact(storagePersistent(a))

	if c.DeleteFact(storageLinear(a)) {
		t.Fatal("a linear fact removed a persistent fact")
	}
	if got := c.CountByName(storageTestFact); got != 1 {
		t.Fatalf("CountByName after the refused deletion = %d, want 1", got)
	}

	c.AddFact(storageLinear(a))
	if got := c.CountByName(storageTestFact); got != 2 {
		t.Fatalf("a linear fact equal to a persistent one was not stored: CountByName = %d, want 2", got)
	}
	if !c.DeleteFact(storageLinear(a)) {
		t.Fatal("the linear fact was not removed")
	}
	remaining := c.Facts()
	if len(remaining) != 1 || !remaining[0].IsPersistent() {
		t.Fatalf("after removing the linear fact, facts = %v, want the persistent fact", remaining)
	}
}

func TestConflictSetFactsPersistentPremisesShareAFact(t *testing.T) {
	t.Parallel()

	x, y := term.NewVariable("x"), term.NewVariable("y")
	a, b := term.NewConstant("a"), term.NewConstant("b")
	body := []*rule.Fact{storagePersistent(x), storagePersistent(y)}

	got := conflictSetFacts([]*rule.Fact{storagePersistent(a)}, body).Values()
	if len(got) != 1 {
		t.Fatalf("two persistent premises against one fact: %d bindings, want 1", len(got))
	}
	for _, v := range []*term.Variable{x, y} {
		if value, ok := got[0].Get(v); !ok || !value.Equal(a) {
			t.Fatalf("binding %v, want %s and %s bound to %s", got[0], x, y, a)
		}
	}

	if got := conflictSetFacts([]*rule.Fact{storagePersistent(a), storagePersistent(b)}, body).Size(); got != 4 {
		t.Fatalf("two persistent premises against two facts: %d bindings, want 4", got)
	}
}

func TestConflictSetFactsMatchesKinds(t *testing.T) {
	t.Parallel()

	x, y := term.NewVariable("x"), term.NewVariable("y")
	a, b := term.NewConstant("a"), term.NewConstant("b")

	if got := conflictSetFacts([]*rule.Fact{storagePersistent(a)}, []*rule.Fact{storageLinear(x)}).Size(); got != 0 {
		t.Fatalf("a linear premise matched a persistent fact: %d bindings", got)
	}
	if got := conflictSetFacts([]*rule.Fact{storageLinear(a)}, []*rule.Fact{storagePersistent(x)}).Size(); got != 0 {
		t.Fatalf("a persistent premise matched a linear fact: %d bindings", got)
	}

	got := conflictSetFacts(
		[]*rule.Fact{storageLinear(a), storagePersistent(b)},
		[]*rule.Fact{storageLinear(x), storagePersistent(y)},
	).Values()
	if len(got) != 1 {
		t.Fatalf("one premise of each kind: %d bindings, want 1", len(got))
	}
	if value, _ := got[0].Get(x); value == nil || !value.Equal(a) {
		t.Fatalf("binding %v, want the linear premise bound to %s", got[0], a)
	}
	if value, _ := got[0].Get(y); value == nil || !value.Equal(b) {
		t.Fatalf("binding %v, want the persistent premise bound to %s", got[0], b)
	}
}

func TestComputeRequirementsCountsPersistentPremisesOnce(t *testing.T) {
	t.Parallel()

	x, y := term.NewVariable("x"), term.NewVariable("y")
	other := func(args ...term.Term) *rule.Fact { return rule.NewFact(storageTestDone, args, rule.LinearFact) }
	got := computeRequirements([]*rule.Fact{storagePersistent(x), storagePersistent(y), other(x), other(y)})
	want := map[string]int{storageTestFact: 1, storageTestDone: 2}
	if !maps.Equal(got, want) {
		t.Fatalf("computeRequirements = %v, want %v", got, want)
	}
}

// TestMonitorPersistentFactSatisfiesSeveralPremises learns a persistent fact
// once, applies a rule whose two persistent premises both match it, learns
// the fact again without storing a second copy, and consumes the linear
// result of the rule once.
func TestMonitorPersistentFactSatisfiesSeveralPremises(t *testing.T) {
	t.Parallel()

	x, y := term.NewVariable("x"), term.NewVariable("y")
	a := term.NewConstant("a")
	done := func(args ...term.Term) *rule.Fact { return rule.NewFact(storageTestDone, args, rule.LinearFact) }
	rules := []*rule.Rule{
		triggerRule(storageTestRuleName+"Learn", nil, []*rule.Fact{storagePersistent(x)}, nil,
			eventTerm(storageTestLearn, x)),
		triggerRule(storageTestRuleName+"Use", []*rule.Fact{storagePersistent(x), storagePersistent(y)},
			[]*rule.Fact{done(x, y)}, nil,
			eventTerm(storageTestUse, term.NewFunction(term.PairFunctionName, []term.Term{x, y}))),
		triggerRule(storageTestRuleName+"Consume", []*rule.Fact{done(x, y)}, nil, nil,
			eventTerm(storageTestConsume, x)),
	}
	m, err := NewMonitor(rules)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}

	events := []term.Term{
		eventTerm(storageTestLearn, a),
		eventTerm(storageTestUse, term.NewFunction(term.PairFunctionName, []term.Term{a, a})),
		eventTerm(storageTestLearn, a),
		eventTerm(storageTestConsume, a),
	}
	for i, event := range events {
		if _, err := m.ProcessEvent(event); err != nil {
			t.Fatalf("event %d %s: %v", i, event, err)
		}
		configs := m.configs.Values()
		if len(configs) != 1 {
			t.Fatalf("after event %d: %d configurations, want 1", i, len(configs))
		}
		if got := configs[0].CountByName(storageTestFact); got != 1 {
			t.Fatalf("after event %d: %d stored persistent facts, want 1", i, got)
		}
		wantDone := 0
		if i == 1 || i == 2 {
			wantDone = 1
		}
		if got := configs[0].CountByName(storageTestDone); got != wantDone {
			t.Fatalf("after event %d: %d linear results, want %d", i, got, wantDone)
		}
	}
	if _, err := m.ProcessEvent(eventTerm(storageTestConsume, a)); err == nil {
		t.Fatal("the linear result was consumed twice")
	}
}

// bruteForceBindings enumerates the bindings of body against stored facts
// directly: a premise matches only a fact of its kind, a linear fact serves
// at most one premise, and a persistent fact any number of them.
func bruteForceBindings(stored, body []*rule.Fact) []string {
	found := map[string]bool{}
	used := make([]bool, len(stored))
	var match func(i int, b *term.Binding)
	match = func(i int, b *term.Binding) {
		if i == len(body) {
			found[b.String()] = true
			return
		}
		pattern := body[i].Subst(b)
		for j, f := range stored {
			if f.Type != pattern.Type || (f.IsLinear() && used[j]) {
				continue
			}
			delta, err := f.Unify(pattern)
			if err != nil || !pattern.Subst(delta).Equal(f) {
				continue
			}
			used[j] = f.IsLinear()
			match(i+1, b.Extend(delta))
			used[j] = false
		}
	}
	match(0, term.NewBinding())
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TestConflictSetFactsForConfigMatchesBruteForce applies random additions
// and deletions of linear and persistent facts, with many duplicates, and
// compares the configuration with a plain multiset in which persistent
// facts occur at most once: the counts and facts, the hash with that of a
// configuration built from the multiset in another order, the bindings of
// random bodies with a brute force enumeration, and the applicability gate
// with the existence of a binding. A premise may repeat a variable.
func TestConflictSetFactsForConfigMatchesBruteForce(t *testing.T) {
	t.Parallel()

	for _, distinct := range []int{2, 4, 40} {
		r := rand.New(rand.NewPCG(uint64(distinct), 5)) //nolint:gosec // A fixed seed keeps the comparison reproducible.
		values := make([]term.Term, distinct)
		for i := range values {
			values[i] = term.NewConstant("c" + strconv.Itoa(i))
		}
		names := []string{storageTestFact, storageTestDone}
		kind := func() rule.FactType {
			if r.IntN(3) == 0 {
				return rule.PersistentFact
			}
			return rule.LinearFact
		}
		randomFact := func() *rule.Fact {
			if distinct == 40 && r.IntN(2) == 0 {
				// A few frequent facts beside many distinct ones.
				return rule.NewFact(storageTestFact, []term.Term{values[r.IntN(3)]}, rule.LinearFact)
			}
			args := make([]term.Term, 1+r.IntN(2))
			for i := range args {
				args[i] = values[r.IntN(len(values))]
			}
			return rule.NewFact(names[r.IntN(len(names))], args, kind())
		}
		randomPattern := func() *rule.Fact {
			args := make([]term.Term, 1+r.IntN(2))
			for i := range args {
				if r.IntN(3) == 0 {
					args[i] = values[r.IntN(len(values))]
				} else {
					args[i] = term.NewVariable("v" + strconv.Itoa(r.IntN(3)))
				}
			}
			return rule.NewFact(names[r.IntN(len(names))], args, kind())
		}

		matched := 0
		for iteration := range 300 {
			c := NewConfig()
			var reference []*rule.Fact
			for range 1 + r.IntN(100) {
				f := randomFact()
				i := slices.IndexFunc(reference, func(g *rule.Fact) bool { return g.Equal(f) })
				if r.IntN(4) == 0 {
					if c.DeleteFact(f) != (i != -1) {
						t.Fatalf("distinct %d, iteration %d: DeleteFact(%s) disagrees with the multiset", distinct, iteration, f)
					}
					if i != -1 {
						reference = slices.Delete(reference, i, i+1)
					}
					continue
				}
				c.AddFact(f)
				if f.IsLinear() || i == -1 {
					reference = append(reference, f)
				}
			}
			for _, name := range names {
				want := 0
				for _, f := range reference {
					if f.Name == name {
						want++
					}
				}
				if got := c.CountByName(name); got != want {
					t.Fatalf("distinct %d, iteration %d: CountByName(%s) = %d, want %d", distinct, iteration, name, got, want)
				}
			}
			if got, want := sortedFactStrings(c.Facts()), sortedFactStrings(reference); !slices.Equal(got, want) {
				t.Fatalf("distinct %d, iteration %d: facts %v, want %v", distinct, iteration, got, want)
			}
			rebuilt := NewConfig()
			for _, i := range r.Perm(len(reference)) {
				rebuilt.AddFact(reference[i])
			}
			if c.Hash() != rebuilt.Hash() {
				t.Fatalf("distinct %d, iteration %d: Hash differs from a configuration built from the multiset", distinct, iteration)
			}
			for range 3 {
				body := make([]*rule.Fact, 1+r.IntN(3))
				for i := range body {
					body[i] = randomPattern()
				}
				got := sortedBindingStrings(conflictSetFactsForConfig(c, body).Values())
				want := bruteForceBindings(reference, body)
				if !slices.Equal(got, want) {
					t.Fatalf("distinct %d, iteration %d, body %v: bindings %v, want %v", distinct, iteration, body, got, want)
				}
				if len(want) > 0 {
					matched++
					if !canMatchLHS(c, computeRequirements(body)) {
						t.Fatalf("distinct %d, iteration %d: the gate rejected the matching body %v", distinct, iteration, body)
					}
				}
			}
		}
		// Guard against a vacuous comparison.
		if matched < 100 {
			t.Fatalf("distinct %d: only %d bodies matched", distinct, matched)
		}
	}
}

func sortedBindingStrings(bindings []*term.Binding) []string {
	out := make([]string, len(bindings))
	for i, b := range bindings {
		out[i] = b.String()
	}
	slices.Sort(out)
	return out
}

func sortedFactStrings(facts []*rule.Fact) []string {
	out := make([]string, len(facts))
	for i, f := range facts {
		out[i] = f.String()
	}
	slices.Sort(out)
	return out
}

func TestConfigCountsIdenticalLinearFacts(t *testing.T) {
	t.Parallel()

	const copies = 1000
	unit := storageLinear(term.NewFunction(term.PairFunctionName, nil))
	c := NewConfig()
	for range copies {
		c.AddFact(storageLinear(term.NewFunction(term.PairFunctionName, nil)))
	}
	bucket := c.factsByName[storageTestFact]
	if len(bucket.entries) != 1 || bucket.entries[0].count != copies {
		t.Fatalf("bucket after %d identical adds = %+v, want one entry with count %d", copies, bucket, copies)
	}
	if got := c.CountByName(storageTestFact); got != copies {
		t.Fatalf("CountByName = %d, want %d", got, copies)
	}
	if got := len(c.Facts()); got != copies {
		t.Fatalf("Facts = %d facts, want %d", got, copies)
	}

	for range copies - 1 {
		if !c.DeleteFact(unit) {
			t.Fatal("DeleteFact failed while copies remained")
		}
	}
	if got := c.CountByName(storageTestFact); got != 1 {
		t.Fatalf("CountByName after deleting all but one copy = %d, want 1", got)
	}
	single := NewConfig()
	single.AddFact(unit)
	if c.Hash() != single.Hash() {
		t.Fatalf("Hash with one remaining copy = %d, want %d", c.Hash(), single.Hash())
	}
	if !c.DeleteFact(unit) {
		t.Fatal("deleting the last copy failed")
	}
	if _, ok := c.factsByName[storageTestFact]; ok || c.CountByName(storageTestFact) != 0 {
		t.Fatal("deleting the last copy did not remove the bucket")
	}
	if c.DeleteFact(unit) {
		t.Fatal("DeleteFact succeeded without a copy left")
	}
}

func TestConfigCountedCopiesCloneIndependently(t *testing.T) {
	t.Parallel()

	a := term.NewConstant("a")
	withCopies := func(n int) *Config {
		c := NewConfig()
		for range n {
			c.AddFact(storageLinear(a))
		}
		return c
	}

	c := withCopies(3)
	d := c.Clone()
	d.AddFact(storageLinear(a))
	if !c.DeleteFact(storageLinear(a)) {
		t.Fatal("DeleteFact on the source failed")
	}
	if got := c.CountByName(storageTestFact); got != 2 {
		t.Fatalf("source copies = %d, want 2", got)
	}
	if got := d.CountByName(storageTestFact); got != 4 {
		t.Fatalf("clone copies = %d, want 4", got)
	}
	if c.Hash() != withCopies(2).Hash() || d.Hash() != withCopies(4).Hash() {
		t.Fatal("hashes after independent changes differ from freshly built configurations")
	}
}

func TestConflictSetFactsForConfigUsesCountedCopies(t *testing.T) {
	t.Parallel()

	x, y := term.NewVariable("x"), term.NewVariable("y")
	a := term.NewConstant("a")
	body := []*rule.Fact{storageLinear(x), storageLinear(y)}
	for _, tc := range []struct {
		copies, bindings int
	}{{1, 0}, {2, 1}, {1000, 1}} {
		c := NewConfig()
		for range tc.copies {
			c.AddFact(storageLinear(a))
		}
		if got := conflictSetFactsForConfig(c, body).Size(); got != tc.bindings {
			t.Fatalf("%d copies: %d bindings, want %d", tc.copies, got, tc.bindings)
		}
		if got := len(appendConstCandidates(nil, c.factsByName[storageTestFact], body, storageTestFact, len(body))); got != min(tc.copies, len(body)) {
			t.Fatalf("%d copies: %d candidates, want %d", tc.copies, got, min(tc.copies, len(body)))
		}
	}
}

// BenchmarkConfigManyIdenticalLinearFacts clones a configuration that holds
// many identical linear facts, adds one more, hashes it and matches a
// pattern of their name, as a monitor does after every event of a trace
// whose rules keep producing the same conclusion.
func BenchmarkConfigManyIdenticalLinearFacts(b *testing.B) {
	const copies = 10000
	unit := func() *rule.Fact { return storageLinear(term.NewFunction(term.PairFunctionName, nil)) }
	c := NewConfig()
	for range copies {
		c.AddFact(unit())
	}
	body := []*rule.Fact{storageLinear(term.NewVariable("x"))}

	b.ReportAllocs()
	for b.Loop() {
		d := c.Clone()
		d.AddFact(unit())
		_ = d.Hash()
		if conflictSetFactsForConfig(d, body).Empty() {
			b.Fatal("no binding")
		}
	}
}

// TestConfigHashCountsEveryCopy distinguishes configurations with the same
// distinct facts in different multiplicities, which a hash that adds each
// counted entry only once would merge.
func TestConfigHashCountsEveryCopy(t *testing.T) {
	t.Parallel()

	f, g := storageLinear(term.NewConstant("f")), storageLinear(term.NewConstant("g"))
	build := func(facts ...*rule.Fact) *Config {
		c := NewConfig()
		for _, fact := range facts {
			c.AddFact(fact)
		}
		return c
	}
	ffg, fgg := build(f, f, g), build(f, g, g)
	if ffg.Hash() == fgg.Hash() {
		t.Fatal("Hash does not distinguish [F, F, G] from [F, G, G]")
	}
}

func TestFactEqualityPreservesCoerciveStorageDeletion(t *testing.T) {
	text := term.NewConstant("ab")
	octets := term.NewConstant([]byte("ab"))
	fact := func(kind rule.FactType, v term.Term) *rule.Fact { return rule.NewFact("State", []term.Term{v}, kind) }
	c := NewConfig()
	c.AddFact(fact(rule.PersistentFact, text))
	c.AddFact(fact(rule.PersistentFact, octets))
	if c.CountByName("State") != 1 {
		t.Fatal("persistent coercive duplicates no longer coalesce")
	}
	c.AddFact(fact(rule.LinearFact, text))
	c.AddFact(fact(rule.LinearFact, octets))
	if c.CountByName("State") != 3 {
		t.Fatal("linear multiplicity or kind separation changed")
	}
	for range 2 {
		if !c.DeleteFact(fact(rule.LinearFact, octets)) {
			t.Fatal("coercively matching linear fact was not deleted")
		}
	}
	if c.DeleteFact(fact(rule.LinearFact, octets)) {
		t.Fatal("linear deletion removed a persistent fact")
	}
	fs := c.Facts()
	if len(fs) != 1 || !fs[0].IsPersistent() {
		t.Fatalf("facts=%v", fs)
	}
	if _, ok := fs[0].Args[0].(*term.Constant[string]); !ok {
		t.Fatal("first stored representation was changed")
	}
}
