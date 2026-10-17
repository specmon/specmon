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

// TestPremiseCandidatesMatchPremisesFirst checks that narrowing the
// premises by an event's values gives the bindings of matching the premises
// alone, restricted to those under which the trigger matches the event: in
// the same order, with each shared variable bound by the same fact, also for
// a fact that is not evaluated yet. Each premise is narrowed by its own
// values, so premises of one name give no more bindings than they allow.
func TestPremiseCandidatesMatchPremisesFirst(t *testing.T) {
	t.Parallel()

	x, y, z := term.NewVariable("x"), term.NewVariable("y"), term.NewVariable("z")
	str := func(s string) term.Term { return term.NewConstant(s) }
	use := func(v term.Term) term.Term { return eventTerm("use", v) }
	matches := func(r *rule.Rule, event term.Term, candidates *bindingSet) []string {
		var got []string
		for _, b := range candidates.Values() {
			if _, err := event.Unify(r.Triggers()[0].Subst(b)); err == nil {
				got = append(got, b.String())
			}
		}
		return got
	}
	sameName := make([]*rule.Fact, 8)
	sameNameFacts := make([]*rule.Fact, 8)
	sameNameVars := make([]term.Term, 8)
	sameNameValues := make([]term.Term, 8)
	for i := range sameName {
		sameNameVars[i], sameNameValues[i] = term.NewVariable("x"+strconv.Itoa(i)), failureInt(int64(i))
		sameName[i], sameNameFacts[i] = linearFact("P", sameNameVars[i]), linearFact("P", sameNameValues[i])
	}
	message := term.NewFunction(term.CatFunctionName, []term.Term{
		term.NewFunction("int", []term.Term{x, failureInt(8)}),
		term.NewFunction("string", []term.Term{y, x}),
		term.NewFunction("byte", []term.Term{z}),
	})

	for _, test := range []struct {
		name    string
		facts   []*rule.Fact
		body    []*rule.Fact
		trigger term.Term
		event   term.Term
		// most is the most bindings that the narrowed premises may give.
		most int
	}{
		{
			name:  "fact of a shared variable",
			facts: []*rule.Fact{linearFact("P", str("ab")), linearFact("P", str("zz")), linearFact("Q", term.NewConstant([]byte("ab")))},
			body:  []*rule.Fact{linearFact("P", x), linearFact("Q", x)}, trigger: use(x), event: use(term.NewConstant([]byte("ab"))), most: 1,
		},
		{
			name: "order",
			facts: []*rule.Fact{
				linearFact("P", str("chosen"), str("a")), linearFact("P", str("chosen"), str("b")), linearFact("P", str("other"), str("c")),
				linearFact("Q", str("1")), linearFact("Q", str("2")),
			},
			body: []*rule.Fact{linearFact("P", x, y), linearFact("Q", z)}, trigger: use(x), event: use(str("chosen")), most: 4,
		},
		{
			name:  "fact not evaluated yet",
			facts: []*rule.Fact{linearFact("P", term.NewFunction(term.CatFunctionName, []term.Term{term.NewFunction("byte", []term.Term{str("a")})}))},
			body:  []*rule.Fact{linearFact("P", x)}, trigger: use(x), event: use(str("a")), most: 1,
		},
		{
			name: "premises of one name", facts: sameNameFacts, body: sameName,
			trigger: use(term.NewFunction("all", sameNameVars)), event: use(term.NewFunction("all", sameNameValues)), most: 1,
		},
		{
			name: "short bytes encoded by an integer annotation",
			facts: []*rule.Fact{
				linearFact("P", term.NewConstant([]byte{1})),
				linearFact("P", term.NewConstant([]byte{1, 0})),
				linearFact("P", failureInt(1)),
				linearFact("P", term.NewConstant([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0})),
			},
			body: []*rule.Fact{linearFact("P", x)},
			trigger: use(term.NewFunction(term.CatFunctionName, []term.Term{
				term.NewFunction("int", []term.Term{x, term.NewConstant[int64](1)}),
			})),
			event: use(term.NewConstant([]byte{1})), most: 3,
		},
		{
			name: "formatted message prefix",
			facts: []*rule.Fact{
				linearFact("P", term.NewConstant([]byte{2, 0, 0, 0, 0, 0, 0, 0, 'a', 'b', 9})),
				linearFact("P", term.NewConstant([]byte{2, 0, 0, 0, 0, 0, 0, 0, 'a', 'c', 9})),
			},
			body:    []*rule.Fact{linearFact("P", message)},
			trigger: use(term.NewFunction("inputs", []term.Term{x, y})),
			event:   use(term.NewFunction("inputs", []term.Term{failureInt(2), str("ab")})), most: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			c := NewConfig()
			for _, f := range test.facts {
				c.AddFact(f)
			}
			r := triggerRule("PremisesFirst", test.body, nil, nil, test.trigger)
			u, err := test.event.Unify(test.trigger)
			if err != nil {
				t.Fatalf("event does not match the trigger: %v", err)
			}
			narrowed := premiseCandidates(c, r, u, nil)
			want := matches(r, test.event, conflictSetFactsForConfig(c, test.body))
			if got := matches(r, test.event, narrowed); !slices.Equal(got, want) || len(want) == 0 {
				t.Fatalf("narrowed bindings = %v, want %v", got, want)
			}
			if narrowed.Size() > test.most {
				t.Fatalf("narrowed premises gave %d bindings, want at most %d", narrowed.Size(), test.most)
			}
		})
	}
}

// A formatted annotation can convert a short byte value to an integer.
// Its direct match then binds the canonical integer, whose eight bytes
// differ from the premise value. Narrowing must retain the premise value.
func TestFormattedNarrowingPreservesShortIntegerBytes(t *testing.T) {
	x := term.NewVariable("x")
	cat := func(kind string, args ...term.Term) term.Term {
		return term.NewFunction(term.CatFunctionName, []term.Term{term.NewFunction(kind, args)})
	}
	c := NewConfig()
	c.AddFact(linearFact("P", term.NewConstant([]byte{1})))
	r := triggerRule("ShortInteger", []*rule.Fact{linearFact("P", cat("byte", x))}, nil, nil,
		eventTerm("use", cat("int", x, term.NewConstant[int64](1))))
	event := eventTerm("use", term.NewConstant([]byte{1}))
	u, err := event.Unify(r.Triggers()[0])
	if err != nil {
		t.Fatal(err)
	}
	var want, got []string
	for _, b := range conflictSetFactsForConfig(c, r.LHS).Values() {
		if _, err := event.Unify(r.Triggers()[0].Subst(b)); err == nil {
			want = append(want, b.String())
		}
	}
	for _, b := range premiseCandidates(c, r, u, nil).Values() {
		if _, err := event.Unify(r.Triggers()[0].Subst(b)); err == nil {
			got = append(got, b.String())
		}
	}
	if len(want) != 1 || !slices.Equal(got, want) {
		t.Fatalf("narrowed bindings = %v, want %v", got, want)
	}
}

func TestFormattedAnnotationKeepsShortBytePremise(t *testing.T) {
	for _, hint := range []bool{false, true} {
		t.Run(strconv.FormatBool(hint), func(t *testing.T) {
			x := term.NewVariable("x")
			seed := triggerRule("Seed", nil, []*rule.Fact{linearFact("State", x)}, nil, eventTerm("seed", x))
			call := eventTerm("use", term.NewFunction(term.CatFunctionName, []term.Term{
				term.NewFunction("int", []term.Term{x, failureInt(1)}),
			}))
			body := []*rule.Fact{linearFact("State", x)}
			rules := []*rule.Rule{seed}
			if hint {
				rules = append(rules, hintRule("Hint", body, []*rule.Fact{linearFact("Hinted", x)}, nil, call))
				body = []*rule.Fact{linearFact("Hinted", x)}
			}
			rules = append(rules, triggerRule("Use", body, []*rule.Fact{linearFact("Done", x)}, nil, call))
			m := newEpsilonTestMonitor(t, rules...)
			value := term.NewConstant([]byte{1})
			for _, event := range []term.Term{eventTerm("seed", value), eventTerm("use", value)} {
				if _, err := m.ProcessEvent(event); err != nil {
					t.Fatal(err)
				}
			}
			var got []string
			for _, c := range m.Configs() {
				for _, f := range c.Facts() {
					got = append(got, f.String())
				}
			}
			if !slices.Equal(got, []string{"Done(0x01)"}) {
				t.Fatalf("facts = %v, want the original short byte value", got)
			}
		})
	}
}

// P binds x to short bytes before Value compares its string bytewise.
// An integer annotation instead parses x as int64. Narrowing must keep
// Value even though that fact cannot itself supply an integer binding.
func TestFormattedAnnotationKeepsSharedStringFact(t *testing.T) {
	for _, prefix := range []bool{false, true} {
		for _, mode := range []string{"trigger", "hint", "multi-use-first", "multi-ack-first"} {
			t.Run(mode+"/prefix="+strconv.FormatBool(prefix), func(t *testing.T) {
				x, y, n := term.NewVariable("x"), term.NewVariable("y"), term.NewVariable("n")
				format := func(kind string) term.Term {
					var fields []term.Term
					if prefix {
						fields = append(fields, term.NewFunction("int", []term.Term{n, failureInt(1)}))
					}
					fields = append(fields, term.NewFunction(kind, []term.Term{x, failureInt(1)}))
					return term.NewFunction(term.CatFunctionName, fields)
				}
				seed := triggerRule("Seed", nil,
					[]*rule.Fact{linearFact("P", y), linearFact("Value", x)}, nil,
					eventTerm("seed", term.NewFunction("pair", []term.Term{x, y})))
				body := []*rule.Fact{linearFact("P", format("byte")), linearFact("Value", x)}
				call := eventTerm("use", format("int"))
				ack := eventTerm("ack", failureInt(0))
				rules := []*rule.Rule{seed}
				if mode == "hint" {
					hinted := linearFact("Hinted", x)
					if prefix {
						hinted = linearFact("Hinted", n, x)
					}
					rules = append(rules, hintRule("Hint", body, []*rule.Fact{hinted}, nil, call))
					body = []*rule.Fact{hinted}
				}
				triggers := []term.Term{call}
				if mode == "multi-use-first" || mode == "multi-ack-first" {
					triggers = append(triggers, ack)
				}
				rules = append(rules, triggerRule("Use", body, []*rule.Fact{linearFact("Done", x)}, nil, triggers...))
				m := newEpsilonTestMonitor(t, rules...)
				payload := []byte{0x61}
				if prefix {
					payload = append([]byte{5}, payload...)
				}
				value := term.NewConstant(payload)
				events := []term.Term{eventTerm("seed", term.NewFunction("pair", []term.Term{term.NewConstant("a"), value}))}
				if mode == "multi-ack-first" {
					events = append(events, ack)
				}
				events = append(events, eventTerm("use", value))
				if mode == "multi-use-first" {
					events = append(events, ack)
				}
				for _, event := range events {
					if _, err := m.ProcessEvent(event); err != nil {
						t.Fatalf("event %s: %v", event, err)
					}
				}
				var got []string
				for _, c := range m.Configs() {
					for _, f := range c.Facts() {
						got = append(got, f.String())
					}
				}
				if !slices.Equal(got, []string{"Done(0x61)"}) {
					t.Fatalf("facts = %v, want the byte binding from P", got)
				}
			})
		}
	}
}

// Compare narrowing with full premise-first matching across field widths,
// constant types, unknown suffixes and variables already bound by another
// premise. Construct events from actual premise matches, so every tested
// event has an accepted reference path even when the direct annotation
// match gives another representation of its variables.
func TestFormattedNarrowingMatchesPremisesFirst(t *testing.T) {
	x, y := term.NewVariable("x"), term.NewVariable("y")
	values := []term.Term{
		term.NewConstant[int64](0), term.NewConstant[int64](1), term.NewConstant[int64](255),
		term.NewConstant([]byte{}), term.NewConstant([]byte{0}), term.NewConstant([]byte{1}),
		term.NewConstant([]byte{1, 0}), term.NewConstant([]byte{1, 0, 0, 0, 0, 0, 0, 0}),
		term.NewConstant(""), term.NewConstant("a"), term.NewConstant("ab"), term.NewConstant("é"),
	}
	format := func(kind string, width int64, prefix, suffix bool) term.Term {
		var fields []term.Term
		if prefix {
			fields = append(fields, term.NewFunction("byte", []term.Term{term.NewConstant([]byte{2})}))
		}
		args := []term.Term{x}
		if width >= 0 {
			args = append(args, term.NewConstant(width))
		}
		fields = append(fields, term.NewFunction(kind, args))
		if suffix {
			fields = append(fields, term.NewFunction("byte", []term.Term{y}))
		}
		return term.NewFunction(term.CatFunctionName, fields)
	}
	matched := func(r *rule.Rule, event term.Term, candidates *bindingSet) []string {
		var result []string
		for _, b := range candidates.Values() {
			if _, err := event.Unify(r.Triggers()[0].Subst(b)); err == nil {
				result = append(result, b.String())
			}
		}
		return result
	}
	formats := func(surround bool) []term.Term {
		var result []term.Term
		for _, kind := range []string{"byte", "int", "string"} {
			for _, width := range []int64{-1, 0, 1, 2, 8} {
				result = append(result, format(kind, width, false, false))
				if surround {
					result = append(result, format(kind, width, true, false),
						format(kind, width, false, true), format(kind, width, true, true))
				}
			}
		}
		return result
	}
	annotations := formats(false)
	checked := 0
	for _, pattern := range formats(true) {
		for _, value := range values {
			seed := term.BindingFromMap(map[term.Term]term.Term{x: value, y: term.NewConstant([]byte{7})})
			payload, err := term.Evaluate(pattern.Subst(seed))
			if err != nil {
				continue
			}
			for _, boundFirst := range []bool{false, true} {
				c := NewConfig()
				c.AddFact(linearFact("P", payload))
				body := []*rule.Fact{linearFact("P", pattern)}
				if boundFirst {
					c.AddFact(linearFact("Value", value))
					body = append([]*rule.Fact{linearFact("Value", x)}, body...)
				}
				full := conflictSetFactsForConfig(c, body)
				for _, annotation := range annotations {
					trigger := eventTerm("use", annotation)
					r := triggerRule("FormatReference", body, nil, nil, trigger)
					for _, b := range full.Values() {
						event, err := term.Evaluate(trigger.Subst(b))
						if err != nil {
							continue
						}
						u, err := event.Unify(trigger)
						if err != nil {
							continue
						}
						want := matched(r, event, full)
						got := matched(r, event, premiseCandidates(c, r, u, nil))
						if !slices.Equal(got, want) {
							t.Fatalf("pattern %s, trigger %s, payload %s, first %t, value %s: got %v, want %v",
								pattern, trigger, payload, boundFirst, value, got, want)
						}
						checked++
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no reference paths checked")
	}
	t.Logf("checked %d accepted reference paths", checked)
}
