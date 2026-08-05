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

package monitor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// Config is a configuration of the monitor.
//
// Facts are stored bucketed by predicate name in factsByName; there is no
// separate flat slice. CountByName / FactsByName / conflict-set callers
// all go through the bucketed view. The total fact count is tracked
// incrementally in factCount so AddFact/DeleteFact don't have to sum
// buckets, and Facts() materialises a flat view only on demand.
//
// Clone is SYMMETRIC copy-on-write: when c.Clone() returns d, BOTH
// configs share the same bucket slice headers AND both have
// ownedBuckets cleared. The first AddFact / DeleteFact on either side
// allocates a fresh bucket via ensureOwned and records ownership on
// that side only. The other side keeps the original shared array.
// This keeps Clone O(distinct predicate names) and amortises bucket
// copies to actual mutations, while ruling out the silent-corruption
// hazard where the source mutates a bucket the clone still references.
type Config struct {
	// factsByName buckets facts by predicate name so conflictSetFacts can
	// iterate only the relevant predicate. Maintained incrementally by
	// AddFact / DeleteFact / Clone.
	factsByName map[string][]*rule.Fact

	// ownedBuckets[name] is true when this Config owns the slice header
	// at factsByName[name] and is free to mutate it (append in place,
	// slices.Delete). A bucket not in ownedBuckets is shared with the
	// Clone source and must be copied before mutation.
	ownedBuckets map[string]bool

	// factCount is the total number of facts across all buckets, kept in
	// sync with factsByName so callers don't have to sum bucket sizes.
	factCount int

	// seen is a multiset of events that have been seen in the current configuration
	// and that have not been processed yet.
	seen []term.Term

	// trace is a list of action facts that have been recorded in the current configuration.
	trace []*rule.Fact

	// hashCache memoizes Hash() so repeated lookups in HashSet[*Config]
	// don't re-walk all facts/seen/trace per call. Any mutation must
	// call invalidateHash().
	hashCache    uint64
	hashCacheSet bool
}

// NewConfig returns a new configuration.
func NewConfig() *Config {
	return &Config{
		factsByName:  make(map[string][]*rule.Fact),
		ownedBuckets: make(map[string]bool),
		seen:         []term.Term{},
		trace:        []*rule.Fact{},
	}
}

// ensureOwned returns a slice for predicate name that the caller is free
// to mutate. If the current bucket is shared with a Clone source, it's
// copied first.
func (c *Config) ensureOwned(name string) []*rule.Fact {
	if c.ownedBuckets[name] {
		return c.factsByName[name]
	}
	bucket := slices.Clone(c.factsByName[name])
	c.factsByName[name] = bucket
	c.ownedBuckets[name] = true
	return bucket
}

// Facts materialises the flat fact list by concatenating every bucket.
// The returned slice is freshly allocated; the order is bucket-iteration
// order (Go map iteration, not insertion order).
func (c *Config) Facts() []*rule.Fact {
	out := make([]*rule.Fact, 0, c.factCount)
	for _, bucket := range c.factsByName {
		out = append(out, bucket...)
	}
	return out
}

func (c *Config) DeleteFact(t *rule.Fact) bool {
	bucket, ok := c.factsByName[t.Name]
	if !ok {
		return false
	}
	i := slices.IndexFunc(bucket, func(s *rule.Fact) bool {
		return t.Equal(s)
	})
	if i == -1 {
		return false
	}

	// Take ownership before mutating in place. ensureOwned returns the
	// (possibly copied) slice we should now update; the prior i is still
	// valid because the indices match up to the deletion point.
	bucket = c.ensureOwned(t.Name)
	bucket = slices.Delete(bucket, i, i+1)
	if len(bucket) == 0 {
		delete(c.factsByName, t.Name)
		delete(c.ownedBuckets, t.Name)
	} else {
		c.factsByName[t.Name] = bucket
	}
	c.factCount--
	c.invalidateHash()

	log.Tracef("removed %s\n", t)

	return true
}

func (c *Config) AddFact(t *rule.Fact) {
	bucket := c.ensureOwned(t.Name)
	c.factsByName[t.Name] = append(bucket, t)
	c.factCount++
	c.invalidateHash()
}

func (c *Config) Clone() *Config {
	d := NewConfig()
	d.seen = slices.Clone(c.seen)
	d.trace = slices.Clone(c.trace)
	d.factCount = c.factCount

	// Copy the factsByName map header but share the bucket slice headers.
	// d.ownedBuckets is empty (set in NewConfig) so d will copy-on-write
	// on its first mutation per bucket.
	if len(c.factsByName) > 0 {
		d.factsByName = make(map[string][]*rule.Fact, len(c.factsByName))
		for k, v := range c.factsByName {
			d.factsByName[k] = v
		}
	}

	// Symmetric step: relinquish ownership on the source. Any bucket
	// that c previously owned is now shared with d, so the next
	// mutation on c MUST also copy first via ensureOwned. Without this
	// reset, a subsequent c.DeleteFact would short-circuit ensureOwned
	// and slices.Delete would mutate the underlying array d still
	// references, silently corrupting d's view.
	//
	// We allocate a fresh empty map rather than clear() the existing
	// one because callers may have captured the old map header (none
	// do today, but the semantics are simpler if Clone never aliases
	// internal state across the two configs).
	if len(c.ownedBuckets) > 0 {
		c.ownedBuckets = make(map[string]bool)
	}

	return d
}

// FactsAsSliceWithName returns a fresh slice of the facts whose
// predicate name matches. The slice is independent of the Config's
// internal bucket so callers may inspect or sort it without breaking
// factCount, the hash cache, or copy-on-write ownership invariants.
// Returns nil when no fact with that name exists.
//
// Internal call sites that need the bucket WITHOUT the per-call alloc
// (the conflictSet hot path) read c.factsByName[name] directly.
func (c *Config) FactsAsSliceWithName(name string) []*rule.Fact {
	bucket := c.factsByName[name]
	if len(bucket) == 0 {
		return nil
	}
	return slices.Clone(bucket)
}

// CountByName returns how many facts in c carry the given predicate name.
// Used by the rule-applicability gate to skip rules whose LHS requires
// more instances of a predicate than the config currently has. O(1)
// via factsByName.
func (c *Config) CountByName(name string) int {
	return len(c.factsByName[name])
}

// String returns a deterministic textual rendering of the config.
//
// factsByName is a Go map and its iteration order is randomised, so
// the display order needs an explicit sort. Per-bucket facts are also
// sorted so two configs with the same multiset of facts always
// stringify identically. seen is a multiset of terms; same treatment.
// trace is an ordered list (rule-application firing order) and is
// rendered in insertion order.
//
// Determinism here is debug-output hygiene; the monitor does not use
// String() for identity (Config.Hash has an explicit implementation).
func (c *Config) String() string {
	// Sort predicate-name keys for stable outer order.
	names := make([]string, 0, len(c.factsByName))
	for name := range c.factsByName {
		names = append(names, name)
	}
	sort.Strings(names)

	facts := make([]string, 0, c.factCount)
	for _, name := range names {
		bucket := c.factsByName[name]
		bucketStrs := make([]string, len(bucket))
		for i, f := range bucket {
			bucketStrs[i] = f.String()
		}
		// Within a bucket the order is also map-derived (DFS through
		// conflictSet's binding products), so sort for stability.
		sort.Strings(bucketStrs)
		facts = append(facts, bucketStrs...)
	}
	factsStr := strings.Join(facts, "\n")

	seen := make([]string, len(c.seen))
	for i := range c.seen {
		seen[i] = c.seen[i].String()
	}
	sort.Strings(seen)
	seenStr := strings.Join(seen, "\n")

	trace := make([]string, len(c.trace))
	for i := range c.trace {
		trace[i] = c.trace[i].String()
	}
	traceStr := strings.Join(trace, "\n")

	return fmt.Sprintf("{ [ %s ] | %s | %s }", factsStr, seenStr, traceStr)
}

// Hash returns a canonical 64-bit digest of the configuration. The result
// is independent of the order in which facts were added (multiset
// semantics) but DEPENDS on multiplicity: [F, F] hashes differently from
// [F] and from []. This is required for correctness because
// data.HashMap.Set keys solely by the returned hash (no Equal fallback),
// so any cardinality collision would silently merge structurally
// distinct configurations.
//
// Implementation: each fact / seen-event contributes a 64-bit mixed
// hash that is then ADDED (uint64, wrapping) into the section
// accumulator. Sum is associative-commutative, so the digest is
// order-independent. Unlike XOR, sum does not cancel duplicates:
// 2 * h(F) != 0, so [F, F] and [] produce different accumulators.
// Sum is O(N) with zero allocations, matching the original XOR
// implementation's hot-path cost.
//
// Each fact hash is "mixed" through a multiplier before summing.
// Without mixing, raw 64-bit FNV-1a values cluster in the low bits
// for short keys and the sum becomes biased. The mixer is a single
// xorshift+multiply step from splitmix64, which is cheap and
// produces a good avalanche.
//
// The three sections are folded into one final FNV-1a value with a
// section-tag byte and section length so a fact and a seen-event
// with equal hashes contribute distinct bytes, and so sections of
// different lengths cannot alias.
//
// The result is memoised in hashCache; mutators must call invalidateHash.
func (c *Config) Hash() uint64 {
	if c.hashCacheSet {
		return c.hashCache
	}

	var factsAcc uint64
	for _, bucket := range c.factsByName {
		for _, f := range bucket {
			factsAcc += mix64(f.Hash())
		}
	}

	var seenAcc uint64
	for _, t := range c.seen {
		seenAcc += mix64(t.Hash())
	}

	// trace is ordered: rule applications are recorded in firing
	// order. Multiply by a step constant so swapping two entries
	// changes the digest. If trace ever becomes a multiset, replace
	// this loop with the sum pattern above.
	var traceAcc uint64
	for i, f := range c.trace {
		traceAcc += mix64(f.Hash()) * uint64(i+1)
	}

	h := fnv.New64a()
	var buf [8]byte
	// Sections are tagged + length-prefixed so cross-section
	// aliasing on equal accumulator values is impossible.
	h.Write([]byte{hashSectionFacts})
	// factCount is a fact tally maintained by AddFact/DeleteFact and is
	// never negative, so the uint64 conversion cannot overflow.
	binary.LittleEndian.PutUint64(buf[:], uint64(c.factCount)) //nolint:gosec
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], factsAcc)
	h.Write(buf[:])

	h.Write([]byte{hashSectionSeen})
	binary.LittleEndian.PutUint64(buf[:], uint64(len(c.seen)))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], seenAcc)
	h.Write(buf[:])

	h.Write([]byte{hashSectionTrace})
	binary.LittleEndian.PutUint64(buf[:], uint64(len(c.trace)))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], traceAcc)
	h.Write(buf[:])

	c.hashCache = h.Sum64()
	c.hashCacheSet = true
	return c.hashCache
}

// mix64 is the splitmix64 finalizer (Stafford variant 13). It
// scrambles low-bit clustering in FNV-1a output so the per-section
// sum has good avalanche even when many input hashes share their
// low bits.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// Section tags used in Hash(); changing these values invalidates the
// memoised digests of any persisted configuration set, but those are
// never written to disk so a renumbering is safe.
const (
	hashSectionFacts byte = 1
	hashSectionSeen  byte = 2
	hashSectionTrace byte = 3
)

// invalidateHash clears the memoized Hash. Callers that mutate facts,
// seen, or trace must call this so the next Hash() recomputes.
func (c *Config) invalidateHash() {
	c.hashCache = 0
	c.hashCacheSet = false
}

func (c *Config) AddSeen(t term.Term) {
	c.seen = append(c.seen, t)
	c.invalidateHash()
}

func (c *Config) DeleteSeen(t term.Term) bool {
	i := slices.IndexFunc(c.seen, func(s term.Term) bool {
		return t.Equal(s)
	})

	if i == -1 {
		return false
	}

	c.seen = slices.Delete(c.seen, i, i+1)
	c.invalidateHash()

	return true
}

// ApplyRule applies a rule to a configuration and returns the resulting configuration.
// If ev is a tuple of the form <fn, ret>, then fn is replaced by ret.
func (c *Config) ApplyRule(r *rule.Rule, b *term.Binding) (*Config, []*rule.Fact, error) {
	log.Infof("   applying rule %s\n", r.Name)

	s := r.Subst(b)
	t := r.Subst(b)

	for _, f := range s.Triggers() {
		t = t.Subst(splitTupleBinding(f))
	}
	t = t.ReplaceFormats()

	if !t.IsGround() {
		return nil, nil, fmt.Errorf("expected ground rule (%s), got variables: %v", t.Name, s.Vars())
	}

	d := c.Clone()

	// Delete the facts from the LHS.
	for _, f := range t.LHS {
		if f.IsLinear() && !d.DeleteFact(f) {
			return nil, nil, fmt.Errorf("cannot delete non-existing fact '%s'", f)
		}
	}

	// Add the facts from the RHS.
	for _, f := range t.RHS {
		if !strings.HasSuffix(f.Name, "_") {
			d.AddFact(f)
		}
	}

	// Remove triggers from seen events.
	// Triggers in s still contain formats.
	for _, f := range s.Triggers() {
		if !d.DeleteSeen(term.ReplaceFormats(f)) {
			return nil, nil, fmt.Errorf("cannot delete non-existing event '%s'", f)
		}
	}

	// Add action facts to trace.
	// FIXME: For performance reasons, this is commented out.
	// d.trace = append(d.trace, t.Act...)

	// Check if special event restrictions are satisfied.
	if err := restrSatisfied(t.Act); err != nil {
		// Don't wrap restriction violations to avoid redundant error messages
		if errors.Is(err, ErrRestrictionViolated) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("rule not applied: %w", err)
	}

	return d, t.Act, nil
}

func splitTupleBinding(a term.Term) *term.Binding {
	b := term.NewBinding()

	fst, snd := splitPair(a)
	if fst == nil || snd == nil {
		return b
	}

	b.Set(fst, snd)

	return b
}

func splitPair(t term.Term) (term.Term, term.Term) {
	f, err := term.AsFunction(t)
	if err != nil || f == nil {
		return nil, nil
	}

	if f.Name != term.PairFunctionName || len(f.Args) != 2 {
		return nil, nil
	}

	fst := f.Args[0]
	snd := f.Args[1]

	return fst, snd
}

func restrSatisfied(trace []*rule.Fact) error {
	for _, t := range trace {
		switch t.Name {
		case "Eq", "Equal":
			if len(t.Args) != 2 {
				return fmt.Errorf("event restriction: %s must have two arguments", t.Name)
			}
			if !t.Args[0].Equal(t.Args[1]) {
				return fmt.Errorf("%w: %s", ErrRestrictionViolated, t)
			}
		case "Neq", "NotEqual", "Unequal":
			if len(t.Args) != 2 {
				return fmt.Errorf("event restriction: %s must have two arguments", t.Name)
			}
			if t.Args[0].Equal(t.Args[1]) {
				return fmt.Errorf("%w: %s", ErrRestrictionViolated, t)
			}
		}
	}

	return nil
}
