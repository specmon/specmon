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
	"math"
	"slices"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

type conflictKey struct {
	name  string
	arity int
}

type itemBucket struct {
	indices    []int
	constIndex map[int]map[uint64][]int
}

type constPos struct {
	pos  int
	term term.Term
	hash uint64
}

type formatConstraint struct {
	minLen int
	maxLen int
	ok     bool
}

type argConstraints struct {
	arity                int
	constPositions       []constPos
	disallowConstant     []bool
	hasDisallowConstant  bool
	formatConstraints    []formatConstraint
	hasFormatConstraints bool
}

type keyIndexNeeds struct {
	constPositions map[int]struct{}
}

func buildArgConstraints(pArgs []term.Term) argConstraints {
	constraints := argConstraints{
		arity: len(pArgs),
	}
	if len(pArgs) == 0 {
		return constraints
	}
	constraints.disallowConstant = make([]bool, len(pArgs))
	constraints.formatConstraints = make([]formatConstraint, len(pArgs))

	for pos, arg := range pArgs {
		if arg.GetType() == term.ConstantType {
			constraints.constPositions = append(constraints.constPositions, constPos{
				pos:  pos,
				term: arg,
				hash: arg.Hash(),
			})
		}

		fn, err := term.AsFunction(arg)
		if err != nil || fn == nil {
			continue
		}
		if !fn.MayEvalToConstant() {
			constraints.disallowConstant[pos] = true
			constraints.hasDisallowConstant = true
		}
		if fc, ok := formatConstraintForCat(fn); ok {
			constraints.formatConstraints[pos] = fc
			constraints.hasFormatConstraints = true
		}
	}

	return constraints
}

func collectIndexNeeds[T Unifier[T]](body []T, indexable func(T) bool, name func(T) string, constraintsByBody []argConstraints) (map[conflictKey]*keyIndexNeeds, bool) {
	needsByKey := make(map[conflictKey]*keyIndexNeeds)
	needAllIndices := false

	for i, p := range body {
		constraints := constraintsByBody[i]
		if !indexable(p) {
			needAllIndices = true
			continue
		}

		key := conflictKey{name: name(p), arity: constraints.arity}
		needs := needsByKey[key]
		if needs == nil {
			needs = &keyIndexNeeds{}
			needsByKey[key] = needs
		}

		if len(constraints.constPositions) == 0 {
			continue
		}
		if needs.constPositions == nil {
			needs.constPositions = make(map[int]struct{}, len(constraints.constPositions))
		}
		for _, cp := range constraints.constPositions {
			needs.constPositions[cp.pos] = struct{}{}
		}
	}

	return needsByKey, needAllIndices
}

func (c *argConstraints) matchesArgs(fArgs []term.Term) bool {
	if len(fArgs) != c.arity {
		return false
	}
	for _, cp := range c.constPositions {
		if !cp.term.Equal(fArgs[cp.pos]) {
			return false
		}
	}
	if c.hasDisallowConstant {
		for pos, disallow := range c.disallowConstant {
			if disallow && fArgs[pos].GetType() == term.ConstantType {
				return false
			}
		}
	}
	if c.hasFormatConstraints {
		for pos, fc := range c.formatConstraints {
			if !fc.ok {
				continue
			}
			if fArgs[pos].GetType() != term.ConstantType {
				continue
			}
			length, ok := constantByteLen(fArgs[pos])
			if !ok {
				continue
			}
			if length < fc.minLen {
				return false
			}
			if fc.maxLen >= 0 && length > fc.maxLen {
				return false
			}
		}
	}
	return true
}

func selectConstCandidates(constIndex map[int]map[uint64][]int, constPositions []constPos) []int {
	var base []int
	for _, cp := range constPositions {
		posMap := constIndex[cp.pos]
		if posMap == nil {
			return nil
		}
		list := posMap[cp.hash]
		if len(list) == 0 {
			return nil
		}
		if base == nil || len(list) < len(base) {
			base = list
		}
	}
	return base
}

func formatConstraintForCat(fn *term.Function) (formatConstraint, bool) {
	if fn.Name != term.CatFunctionName {
		return formatConstraint{}, false
	}
	total := 0
	for i, field := range fn.Args {
		fieldFn, err := term.AsFunction(field)
		if err != nil || fieldFn == nil {
			return formatConstraint{}, false
		}
		length, known, variable := formatFieldLength(fieldFn)
		switch {
		case known && length >= 0:
			if length > math.MaxInt-total {
				return formatConstraint{}, false
			}
			total += length
		case variable:
			if i != len(fn.Args)-1 {
				return formatConstraint{}, false
			}
			return formatConstraint{minLen: total, maxLen: -1, ok: true}, true
		default:
			return formatConstraint{}, false
		}
	}
	return formatConstraint{minLen: total, maxLen: total, ok: true}, true
}

func formatFieldLength(field *term.Function) (int, bool, bool) {
	if len(field.Args) == 2 {
		length, err := term.AsInt(field.Args[1])
		if err != nil || length < 0 {
			return 0, false, false
		}
		if length > math.MaxInt {
			return 0, false, false
		}
		return int(length), true, false
	}
	if len(field.Args) != 1 {
		return 0, false, false
	}
	if length, ok := constantByteLen(field.Args[0]); ok {
		return length, true, false
	}
	if _, err := term.AsVariable(field.Args[0]); err == nil {
		return 0, false, true
	}
	return 0, false, false
}

func constantByteLen(t term.Term) (int, bool) {
	switch c := t.(type) {
	case *term.Constant[int64]:
		return 8, true
	case *term.Constant[string]:
		return len(c.Value), true
	case *term.Constant[[]byte]:
		return len(c.Value), true
	default:
		return 0, false
	}
}

// conflictSetSingle matches a single pattern p against items. If
// persistent is not nil, p matches only items of its kind.
func conflictSetSingle[T Unifier[T]](items []T, p T, indexable func(T) bool, name func(T) string, args func(T) []term.Term, persistent func(T) bool) *bindingSet {
	result := newBindingSet()

	pArgs := args(p)
	constraints := buildArgConstraints(pArgs)

	indexedPattern := indexable(p)
	pName := ""
	if indexedPattern {
		pName = name(p)
	}

	for _, item := range items {
		itemArgs := args(item)

		if indexedPattern {
			if !indexable(item) || name(item) != pName || len(itemArgs) != len(pArgs) {
				continue
			}
		}
		if persistent != nil && persistent(item) != persistent(p) {
			continue
		}

		// Only apply the argument prefilter when the pattern actually carries a
		// constraint. matchesArgs gates on arity first, so an unconstrained
		// pattern (a bare variable or a constant, arity 0) would otherwise
		// reject every item with arguments before Unify runs. This mirrors the
		// guard in the multi-pattern path.
		if len(constraints.constPositions) > 0 || constraints.hasDisallowConstant || constraints.hasFormatConstraints {
			if !constraints.matchesArgs(itemArgs) {
				continue
			}
		}

		delta, err := item.Unify(p)
		if err != nil {
			continue
		}
		result.Add(delta)
	}

	return result
}

// conflictSet matches the patterns of body against items, using every item
// at most once per binding. If persistent is not nil, a pattern matches
// only items of its kind, and a persistent item may serve several patterns
// of one binding. A match does not consume it.
func conflictSet[T Unifier[T]](
	items []T,
	body []T,
	indexable func(T) bool,
	name func(T) string,
	args func(T) []term.Term,
	persistent func(T) bool,
) *bindingSet {
	log.Debugf("conflictSet( items=%d, body=%d )\n", len(items), len(body))

	if len(body) == 1 {
		return conflictSetSingle(items, body[0], indexable, name, args, persistent)
	}

	constraintsByBody := make([]argConstraints, len(body))
	for i, p := range body {
		constraintsByBody[i] = buildArgConstraints(args(p))
	}
	needsByKey, needAllIndices := collectIndexNeeds(body, indexable, name, constraintsByBody)

	// Index items by name+arity and per-argument constants.
	itemsByKey := make(map[conflictKey]*itemBucket, len(needsByKey))
	for i, item := range items {
		if !indexable(item) {
			continue
		}
		itemArgs := args(item)
		key := conflictKey{name: name(item), arity: len(itemArgs)}
		needs := needsByKey[key]
		if needs == nil {
			continue
		}

		bucket := itemsByKey[key]
		if bucket == nil {
			constIndexCap := 0
			if needs.constPositions != nil {
				constIndexCap = len(needs.constPositions)
			}
			bucket = &itemBucket{
				constIndex: make(map[int]map[uint64][]int, constIndexCap),
			}
			itemsByKey[key] = bucket
		}
		bucket.indices = append(bucket.indices, i)
		if len(needs.constPositions) == 0 {
			continue
		}
		for pos, arg := range itemArgs {
			if _, ok := needs.constPositions[pos]; !ok {
				continue
			}
			if arg.GetType() != term.ConstantType {
				continue
			}
			posMap := bucket.constIndex[pos]
			if posMap == nil {
				posMap = make(map[uint64][]int)
				bucket.constIndex[pos] = posMap
			}
			h := arg.Hash()
			posMap[h] = append(posMap[h], i)
		}
	}

	// Pre-filter candidates per body atom by constant positions for ordering.
	n := len(body)
	prefilter := make([][]int, n)
	order := make([]int, n)

	var allIndices []int
	if needAllIndices {
		allIndices = make([]int, len(items))
		for j := range items {
			allIndices[j] = j
		}
	}

	for i, p := range body {
		constraints := constraintsByBody[i]

		var candIndices []int
		if indexable(p) {
			key := conflictKey{name: name(p), arity: constraints.arity}
			bucket := itemsByKey[key]
			if bucket == nil || len(bucket.indices) == 0 {
				// No matches possible at all.
				return newBindingSet()
			}
			candIndices = bucket.indices
			if len(constraints.constPositions) > 0 {
				candIndices = selectConstCandidates(bucket.constIndex, constraints.constPositions)
				if len(candIndices) == 0 {
					return newBindingSet()
				}
			}
		} else {
			// Fallback: no indexing possible, scan all items.
			candIndices = allIndices
		}
		if persistent != nil {
			otherKind := func(idx int) bool { return persistent(items[idx]) != persistent(p) }
			if slices.ContainsFunc(candIndices, otherKind) {
				candIndices = slices.DeleteFunc(slices.Clone(candIndices), otherKind)
			}
		}

		if len(constraints.constPositions) == 0 && !constraints.hasDisallowConstant && !constraints.hasFormatConstraints {
			prefilter[i] = candIndices
			order[i] = i
			continue
		}

		filtered := make([]int, 0, len(candIndices))
		for _, idx := range candIndices {
			fArgs := args(items[idx])
			if constraints.matchesArgs(fArgs) {
				filtered = append(filtered, idx)
			}
		}

		prefilter[i] = filtered
		order[i] = i
	}
	// Sort atoms by increasing number of prefiltered candidates to prune early.
	sort.Slice(order, func(i, j int) bool { return len(prefilter[order[i]]) < len(prefilter[order[j]]) })

	result := newBindingSet()

	// Track which items have been used in the current DFS path. This
	// ensures multiset semantics s.t. each item can only be consumed once
	// per binding path. Persistent items are never marked used.
	// Use a binding trail (mark/unwind) so the DFS reuses one mutable binding
	// instead of cloning at every branch.
	usedItems := make([]bool, len(items))
	trail := term.NewBindingTrail()

	var dfs func(pos int, b *term.Binding)
	dfs = func(pos int, b *term.Binding) {
		if pos == n {
			result.Add(b.Clone())
			return
		}

		idx := order[pos]
		p := body[idx]
		// Apply current binding once per depth.
		ps := p.Subst(b)
		psArgs := args(ps)

		for _, itemIdx := range prefilter[idx] {
			// Skip if this item has already been used in this binding path
			if usedItems[itemIdx] {
				continue
			}

			f := items[itemIdx]
			fArgs := args(f)
			if len(psArgs) == len(fArgs) {
				skip := false
				for i, psArg := range psArgs {
					if psArg.GetType() == term.ConstantType && fArgs[i].GetType() == term.ConstantType {
						if !psArg.Equal(fArgs[i]) {
							skip = true
							break
						}
					}
				}
				if skip {
					continue
				}
			}
			delta, err := f.Unify(ps)
			if err != nil {
				continue
			}
			reuse := persistent != nil && persistent(f)
			if !reuse {
				usedItems[itemIdx] = true
			}
			mark := trail.Mark()
			b.MergeWithTrail(delta, trail)
			dfs(pos+1, b)
			b.Unwind(trail, mark)
			if !reuse {
				usedItems[itemIdx] = false
			}
		}
	}

	dfs(0, term.NewBinding())
	return result
}

// conflictSetFacts matches a sequence of fact patterns against a multiset of facts.
// It builds a per-predicate local index and uses DFS with early filtering by
// constants. A pattern matches only facts of its kind. A linear fact is used
// by at most one pattern per binding. A persistent fact may be used by several.
func conflictSetFacts(facts []*rule.Fact, body []*rule.Fact) *bindingSet {
	return conflictSet(facts, body,
		func(_ *rule.Fact) bool { return true },
		func(f *rule.Fact) string { return f.Name },
		func(f *rule.Fact) []term.Term { return f.Args },
		(*rule.Fact).IsPersistent,
	)
}

// conflictSetFactsForConfig is like conflictSetFacts but draws candidates
// from c.factsByName. It builds the items slice from only the predicate
// buckets a body pattern references, skipping facts whose predicate the
// rule's LHS never mentions. For configs with thousands of unrelated
// facts this keeps the conflict-set pre-pass O(|interesting facts|)
// instead of O(|all facts|). A fact with several copies appears at most
// as often as body has patterns of its name, which is all that the
// conflict set can use, so many copies cost as little as one.
func conflictSetFactsForConfig(c *Config, body []*rule.Fact) *bindingSet {
	// Bodies have a handful of patterns, so scanning them is cheaper than
	// building maps of their names.
	var items []*rule.Fact
	for i, p := range body {
		name := p.Name
		if slices.ContainsFunc(body[:i], func(q *rule.Fact) bool { return q.Name == name }) {
			continue
		}
		slots := 0
		for _, q := range body[i:] {
			if q.Name == name {
				slots++
			}
		}
		items = appendConstCandidates(items, c.factsByName[name], body, name, slots)
	}
	return conflictSetFacts(items, body)
}

// constCandidateMinBucket is the bucket size from which
// appendConstCandidates filters a bucket instead of appending all of it.
const constCandidateMinBucket = 32

// appendConstCandidates appends the facts of bucket that can match at least
// one body pattern named name, judged by the argument checks of matchesArgs.
// A fact with several copies is appended at most slots times. If some
// pattern with that name has no constant argument, the whole bucket is
// appended.
//
// Otherwise conflictSet applies matchesArgs to every candidate of these
// patterns, so it could not match a dropped fact. The kept facts stay in
// bucket order, so filtering changes neither the bindings nor their order
// compared with appending the whole bucket. The filter keeps the per-call
// indexing of conflictSet proportional to the candidates instead of the
// whole bucket, which matters for large persistent buckets.
func appendConstCandidates(items []*rule.Fact, bucket factBucket, body []*rule.Fact, name string, slots int) []*rule.Fact {
	appendEntry := func(e factEntry) {
		for range min(e.count, slots) {
			items = append(items, e.fact)
		}
	}
	appendAll := func() []*rule.Fact {
		for _, e := range bucket.entries {
			appendEntry(e)
		}
		return items
	}
	if len(bucket.entries) < constCandidateMinBucket {
		return appendAll()
	}
	var patterns []argConstraints
	for _, p := range body {
		if p.Name != name {
			continue
		}
		constraints := buildArgConstraints(p.Args)
		if len(constraints.constPositions) == 0 {
			return appendAll()
		}
		patterns = append(patterns, constraints)
	}
	for _, e := range bucket.entries {
		for i := range patterns {
			if patterns[i].matchesArgs(e.fact.Args) {
				appendEntry(e)
				break
			}
		}
	}
	return items
}

type bindingSet struct {
	bindings []*term.Binding
	seen     map[uint64][]int
}

func newBindingSet() *bindingSet {
	return &bindingSet{
		seen: make(map[uint64][]int),
	}
}

func (s *bindingSet) Add(b *term.Binding) bool {
	if b == nil {
		return false
	}
	h := b.HashUnordered()
	for _, idx := range s.seen[h] {
		if s.bindings[idx].Equal(b) {
			return false
		}
	}
	s.seen[h] = append(s.seen[h], len(s.bindings))
	s.bindings = append(s.bindings, b)
	return true
}

func (s *bindingSet) Values() []*term.Binding {
	if s == nil {
		return nil
	}
	return s.bindings
}

func (s *bindingSet) Empty() bool {
	return s == nil || len(s.bindings) == 0
}

func (s *bindingSet) Size() int {
	if s == nil {
		return 0
	}
	return len(s.bindings)
}
