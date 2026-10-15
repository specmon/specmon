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

package monitor

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
	"github.com/specmon/specmon/utils"
)

// Config is a configuration of the monitor.
//
// Facts are stored bucketed by predicate name in factsByName; there is no
// separate flat slice. CountByName / FactsAsSliceWithName / conflict-set
// callers all go through the bucketed view. A bucket holds one entry per
// distinct fact with the number of its copies: a linear fact keeps its
// multiplicity as a count, and a persistent fact has one copy. Facts that
// are equal share an entry, which keeps the representation of the first
// one added. The total fact count, counting copies, is tracked
// incrementally in factCount and per bucket, so AddFact/DeleteFact don't
// have to sum buckets, and Facts() materialises a flat view only on
// demand.
//
// Clone is SYMMETRIC copy-on-write: when c.Clone() returns d, BOTH
// configs share the same entry arrays AND both have ownedBuckets cleared.
// The first AddFact / DeleteFact on either side copies the entries via
// ownedBucket and records ownership on that side only. The other side
// keeps the original shared entries.
// This keeps Clone O(distinct predicate names) and amortises bucket
// copies to actual mutations, while ruling out the silent-corruption
// hazard where the source mutates a bucket the clone still references.
type Config struct {
	// factsByName buckets facts by predicate name so conflictSetFacts can
	// iterate only the relevant predicate. Maintained incrementally by
	// AddFact / DeleteFact / Clone.
	factsByName map[string]factBucket

	// ownedBuckets[name] is true when this Config owns the bucket at
	// factsByName[name] and is free to mutate it (append in place, change
	// a count, slices.Delete). A bucket not in ownedBuckets is shared with
	// the Clone source and must be copied before mutation.
	ownedBuckets map[string]bool

	// factCount is the total number of facts across all buckets, counting
	// copies, kept in sync with factsByName so callers don't have to sum
	// bucket sizes.
	factCount int

	// seen is a multiset of events that have been seen in the current configuration
	// and that have not been processed yet. The monitor does not record
	// events here: a rule with several triggers keeps its progress in pending.
	seen []term.Term

	// pending records partially matched multi-trigger rule applications.
	// Entries are never changed in place, so clones share them.
	pending []pendingApplication

	// trace is a list of action facts that have been recorded in the current configuration.
	trace []*rule.Fact

	// hashCache memoizes Hash() so repeated lookups in HashSet[*Config]
	// don't re-walk all facts/seen/pending/trace per call. Any mutation
	// must call invalidateHash().
	hashCache    uint64
	hashCacheSet bool
}

// factEntry is a distinct stored fact and the number of its copies. A
// persistent fact has exactly one copy.
type factEntry struct {
	fact  *rule.Fact
	count int
}

// factBucket holds the entries of one predicate name in the order in which
// their facts were first added, and the number of copies they hold
// together. Buckets are stored by value, so each configuration has its own
// total. Only the entries array is shared between clones.
type factBucket struct {
	entries []factEntry
	total   int
}

type pendingApplication struct {
	ruleOrdinal int
	binding     *term.Binding
	outstanding []int
}

func (p pendingApplication) equal(q pendingApplication) bool {
	return p.ruleOrdinal == q.ruleOrdinal && slices.Equal(p.outstanding, q.outstanding) && p.binding.Equal(q.binding)
}

// hash includes the rule identity, binding and remaining trigger slots. Slots
// are stored in ascending order; bindings are visited in canonical key order.
func (p pendingApplication) hash() uint64 {
	h := fnv.New64a().Sum64()
	h = utils.FNV64aUint64(h, uint64(p.ruleOrdinal))    //nolint:gosec
	h = utils.FNV64aUint64(h, uint64(p.binding.Size())) //nolint:gosec
	p.binding.IterateSorted(func(key, value term.Term) bool {
		h = utils.FNV64aUint64(h, key.Hash())
		h = utils.FNV64aUint64(h, value.Hash())
		return true
	})
	h = utils.FNV64aUint64(h, uint64(len(p.outstanding)))
	for _, slot := range p.outstanding {
		h = utils.FNV64aUint64(h, uint64(slot)) //nolint:gosec
	}
	return h
}

// NewConfig returns a new configuration.
func NewConfig() *Config {
	return &Config{
		factsByName:  make(map[string]factBucket),
		ownedBuckets: make(map[string]bool),
		seen:         []term.Term{},
		pending:      []pendingApplication{},
		trace:        []*rule.Fact{},
	}
}

// ownedBucket returns the bucket for predicate name with entries that the
// caller is free to mutate. The zero bucket if there is none. If the
// entries are shared with a Clone source, they're copied first. The caller
// stores the changed bucket back into factsByName.
func (c *Config) ownedBucket(name string) factBucket {
	bucket := c.factsByName[name]
	if !c.ownedBuckets[name] {
		bucket.entries = slices.Clone(bucket.entries)
		c.ownedBuckets[name] = true
	}
	return bucket
}

// appendFacts appends every copy of every fact in b to out.
func (b factBucket) appendFacts(out []*rule.Fact) []*rule.Fact {
	for _, e := range b.entries {
		for range e.count {
			out = append(out, e.fact)
		}
	}
	return out
}

// Facts materialises the flat fact list by concatenating every bucket,
// with one element per copy. The returned slice is freshly allocated. The
// order is bucket-iteration order (Go map iteration, not insertion order).
func (c *Config) Facts() []*rule.Fact {
	out := make([]*rule.Fact, 0, c.factCount)
	for _, bucket := range c.factsByName {
		out = bucket.appendFacts(out)
	}
	return out
}

// indexOfFact returns the index of the entry in entries that holds the same
// fact as t, or -1. Hashes are compared first. Fact.Hash covers the name,
// kind and arguments.
func indexOfFact(entries []factEntry, t *rule.Fact) int {
	h := t.Hash()
	return slices.IndexFunc(entries, func(e factEntry) bool {
		return e.fact.Hash() == h && e.fact.Equal(t)
	})
}

// DeleteFact removes one occurrence of t, which must have the same kind as
// the stored fact: a linear fact never removes a persistent one.
func (c *Config) DeleteFact(t *rule.Fact) bool {
	bucket, ok := c.factsByName[t.Name]
	if !ok {
		return false
	}
	i := indexOfFact(bucket.entries, t)
	if i == -1 {
		return false
	}

	if bucket.total == 1 {
		// The last copy: drop the bucket without copying shared entries.
		delete(c.factsByName, t.Name)
		delete(c.ownedBuckets, t.Name)
	} else {
		// Take ownership before mutating in place. ownedBucket returns
		// the (possibly copied) entries we should now update. The prior i
		// is still valid because a copy keeps the order of the entries.
		bucket = c.ownedBucket(t.Name)
		if bucket.entries[i].count > 1 {
			bucket.entries[i].count--
		} else {
			bucket.entries = slices.Delete(bucket.entries, i, i+1)
		}
		bucket.total--
		c.factsByName[t.Name] = bucket
	}
	c.factCount--
	c.invalidateHash()

	log.Tracef("removed %s\n", t)

	return true
}

// AddFact adds t to c. Persistent facts form a set: adding a persistent
// fact that c already holds leaves c unchanged. Linear facts form a
// multiset: adding a linear fact that c already holds counts another copy.
// Finding it scans the bucket, comparing hashes first.
func (c *Config) AddFact(t *rule.Fact) {
	i := indexOfFact(c.factsByName[t.Name].entries, t)
	if i != -1 && t.IsPersistent() {
		return
	}
	bucket := c.ownedBucket(t.Name)
	if i != -1 {
		bucket.entries[i].count++
	} else {
		bucket.entries = append(bucket.entries, factEntry{fact: t, count: 1})
	}
	bucket.total++
	c.factsByName[t.Name] = bucket
	c.factCount++
	c.invalidateHash()
}

func (c *Config) Clone() *Config {
	d := NewConfig()
	d.seen = slices.Clone(c.seen)
	d.pending = slices.Clone(c.pending)
	d.trace = slices.Clone(c.trace)
	d.factCount = c.factCount

	// Copy the factsByName map. The copied buckets share their entries.
	// d.ownedBuckets is empty (set in NewConfig) so d will copy-on-write
	// on its first mutation per bucket.
	d.factsByName = maps.Clone(c.factsByName)

	// Symmetric step: relinquish ownership on the source. Any bucket
	// that c previously owned is now shared with d, so the next
	// mutation on c MUST also copy first via ownedBucket. Without this
	// reset, a subsequent c.DeleteFact would short-circuit ownedBucket
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
// predicate name matches, with one element per copy. The slice is
// independent of the Config's internal bucket so callers may inspect or
// sort it without breaking factCount, the hash cache, or copy-on-write
// ownership invariants. Returns nil when no fact with that name exists.
//
// Internal call sites that need the bucket WITHOUT the per-call alloc
// (the conflictSet hot path) read c.factsByName[name] directly.
func (c *Config) FactsAsSliceWithName(name string) []*rule.Fact {
	bucket, ok := c.factsByName[name]
	if !ok {
		return nil
	}
	return bucket.appendFacts(make([]*rule.Fact, 0, bucket.total))
}

// CountByName returns how many facts in c carry the given predicate name,
// counting copies. Used by the rule-applicability gate to skip rules whose
// LHS requires more instances of a predicate than the config currently
// has. O(1) via factsByName.
func (c *Config) CountByName(name string) int {
	return c.factsByName[name].total
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
		bucket := c.factsByName[name].appendFacts(nil)
		bucketStrs := make([]string, len(bucket))
		for i, f := range bucket {
			bucketStrs[i] = f.String()
		}
		// A bucket keeps the order in which its facts were first added,
		// which differs between configurations with the same facts, so
		// sort for stability.
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
// Implementation: each fact, seen event and pending application
// contributes a 64-bit mixed hash that is then ADDED (uint64,
// wrapping) into the section accumulator. Sum is
// associative-commutative, so the digest is order-independent.
// Unlike XOR, sum does not cancel duplicates:
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
// The four sections are folded into one final FNV-1a value with a
// section-tag byte and section length so a fact and a seen-event
// with equal hashes contribute distinct bytes, and so sections of
// different lengths cannot alias.
//
// The result is memoised in hashCache; mutators must call invalidateHash.
func (c *Config) Hash() uint64 {
	if c.hashCacheSet {
		return c.hashCache
	}

	// A fact with n copies contributes n times its mixed hash, as n
	// separately stored copies would.
	var factsAcc uint64
	for _, bucket := range c.factsByName {
		for _, e := range bucket.entries {
			factsAcc += uint64(e.count) * mix64(e.fact.Hash()) //nolint:gosec // counts are positive
		}
	}

	var seenAcc uint64
	for _, t := range c.seen {
		seenAcc += mix64(t.Hash())
	}

	// Pending applications form a multiset: order is irrelevant, but
	// repeated applications must contribute once per occurrence.
	var pendingAcc uint64
	for _, pending := range c.pending {
		pendingAcc += mix64(pending.hash())
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

	h.Write([]byte{hashSectionPending})
	binary.LittleEndian.PutUint64(buf[:], uint64(len(c.pending)))
	h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], pendingAcc)
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
	hashSectionFacts   byte = 1
	hashSectionSeen    byte = 2
	hashSectionPending byte = 3
	hashSectionTrace   byte = 4
)

// invalidateHash clears the memoized Hash. Callers that mutate facts,
// seen, pending applications or trace must call this so the next
// Hash() recomputes.
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

func (c *Config) addPending(pending pendingApplication) {
	c.pending = append(c.pending, pending)
	c.invalidateHash()
}

func (c *Config) removePending(index int) {
	c.pending = slices.Delete(c.pending, index, index+1)
	c.invalidateHash()
}

func (c *Config) replacePending(index int, pending pendingApplication) {
	c.pending[index] = pending
	c.invalidateHash()
}

func (c *Config) reserveRuleLHS(r *rule.Rule, b *term.Binding, matchedTrigger term.Term) (*Config, error) {
	split := term.BindingFromPair(matchedTrigger.Subst(b))
	lhs := make([]*rule.Fact, len(r.LHS))
	for i, fact := range r.LHS {
		resolved, err := fact.Subst(b).Subst(split).ReplaceFormats()
		if err != nil {
			return nil, fmt.Errorf("evaluate rule %s LHS: %w", r.Name, err)
		}
		if !resolved.IsGround() {
			return nil, fmt.Errorf("expected ground LHS in rule %s, got %s", r.Name, resolved)
		}
		lhs[i] = resolved
	}

	d := c.Clone()
	for _, fact := range lhs {
		if fact.IsLinear() && !d.DeleteFact(fact) {
			return nil, fmt.Errorf("cannot delete non-existing fact '%s'", fact)
		}
	}
	return d, nil
}

func (c *Config) finalizeReservedRule(r *rule.Rule, b *term.Binding) (*Config, []*rule.Fact, error) {
	evaluated, err := r.EvaluateGround(b)
	if err != nil {
		return nil, nil, err
	}

	d := c.Clone()
	for _, fact := range evaluated.RHS {
		if !rule.IsInternalFactName(fact.Name) {
			d.AddFact(fact)
		}
	}
	if err := restrSatisfied(evaluated.Act); err != nil {
		return nil, nil, err
	}
	return d, evaluated.Act, nil
}

// ApplyRule applies a rule to a configuration and returns the resulting configuration.
// If ev is a tuple of the form <fn, ret>, then fn is replaced by ret.
func (c *Config) ApplyRule(r *rule.Rule, b *term.Binding) (*Config, []*rule.Fact, error) {
	log.Infof("   applying rule %s\n", r.Name)

	t, err := r.EvaluateGround(b)
	if err != nil {
		return nil, nil, err
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
		if !rule.IsInternalFactName(f.Name) {
			d.AddFact(f)
		}
	}

	// Add action facts to trace.
	// FIXME: For performance reasons, this is commented out.
	// d.trace = append(d.trace, t.Act...)

	// Check if special event restrictions are satisfied.
	if err := restrSatisfied(t.Act); err != nil {
		return nil, nil, err
	}

	return d, t.Act, nil
}

// restrSatisfied checks the restriction actions of trace. A violated
// restriction is ErrRestrictionViolated; a malformed one is another error.
func restrSatisfied(trace []*rule.Fact) error {
	for _, t := range trace {
		switch t.Name {
		case "Eq", "Equal":
			if len(t.Args) != 2 {
				return fmt.Errorf("rule not applied: event restriction: %s must have two arguments", t.Name)
			}
			if !t.Args[0].Equal(t.Args[1]) {
				return fmt.Errorf("%w: %s", ErrRestrictionViolated, t)
			}
		case "Neq", "NotEqual", "Unequal":
			if len(t.Args) != 2 {
				return fmt.Errorf("rule not applied: event restriction: %s must have two arguments", t.Name)
			}
			if t.Args[0].Equal(t.Args[1]) {
				return fmt.Errorf("%w: %s", ErrRestrictionViolated, t)
			}
		}
	}

	return nil
}
