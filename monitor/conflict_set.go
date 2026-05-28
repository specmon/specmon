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
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

func conflictSet[T Unifier[T]](items []T, body []T, indexable func(T) bool, name func(T) string, args func(T) []term.Term) *data.HashSet[*term.Binding] {
	log.Debugf("conflictSet( items=%d, body=%d )\n", len(items), len(body))

	// Index items by name, keeping track of original indices
	itemsByName := make(map[string][]int, len(items))
	for i, item := range items {
		if indexable(item) {
			itemsByName[name(item)] = append(itemsByName[name(item)], i)
		}
	}

	// Pre-filter candidates per body atom by constant positions for ordering.
	n := len(body)
	prefilter := make([][]int, n)
	order := make([]int, n)

	for i, p := range body {
		var candIndices []int
		if indexable(p) {
			candIndices = itemsByName[name(p)]
			if len(candIndices) == 0 {
				// No matches possible at all.
				return data.NewHashSet[*term.Binding]()
			}
			// Filter by constants in p (cheap check before unification).
			filtered := make([]int, 0, len(candIndices))
			for _, idx := range candIndices {
				f := items[idx]
				ok := true
				pArgs := args(p)
				fArgs := args(f)
				// This check assumes len(pArgs) == len(fArgs), which should hold for unification candidates.
				if len(pArgs) == len(fArgs) {
					for j, a := range pArgs {
						if a.GetType() == term.ConstantType {
							if !a.Equal(fArgs[j]) {
								ok = false
								break
							}
						}
					}
				} else {
					ok = false
				}

				if ok {
					filtered = append(filtered, idx)
				}
			}
			prefilter[i] = filtered
		} else {
			// Fallback: no indexing possible, scan all items.
			allIndices := make([]int, len(items))
			for j := range items {
				allIndices[j] = j
			}
			prefilter[i] = allIndices
		}
		order[i] = i
	}
	// Sort atoms by increasing number of prefiltered candidates to prune early.
	sort.Slice(order, func(i, j int) bool { return len(prefilter[order[i]]) < len(prefilter[order[j]]) })

	result := data.NewHashSet[*term.Binding]()

	// Track which items from the original items slice have been used.
	// This ensures multiset semantics s.t. each fact can only be consumed once.
	// Use backtracking (mark/unmark) instead of copying map on each recursive call.
	usedItems := make(map[int]bool)

	var dfs func(pos int, b *term.Binding)
	dfs = func(pos int, b *term.Binding) {
		if pos == n {
			result.Add(b)
			return
		}

		idx := order[pos]
		p := body[idx]
		// Apply current binding once per depth.
		ps := p.Subst(b)

		for _, itemIdx := range prefilter[idx] {
			// Skip if this fact has already been used in this binding path
			if usedItems[itemIdx] {
				continue
			}

			f := items[itemIdx]
			if delta, err := f.Unify(ps); err == nil {
				// Mark item as used (backtracking pattern)
				usedItems[itemIdx] = true
				dfs(pos+1, delta.Extend(b))
				// Unmark item for other branches
				delete(usedItems, itemIdx)
			}
		}
	}

	dfs(0, term.NewBinding())
	return result
}

// conflictSetFacts matches a sequence of fact patterns against a multiset of facts.
// It builds a per-predicate local index and uses DFS with early filtering by constants.
func conflictSetFacts(facts []*rule.Fact, body []*rule.Fact) *data.HashSet[*term.Binding] {
	return conflictSet(facts, body,
		func(_ *rule.Fact) bool { return true },
		func(f *rule.Fact) string { return f.Name },
		func(f *rule.Fact) []term.Term { return f.Args },
	)
}

// conflictSetTerms matches a sequence of term patterns against a set of seen terms.
// It builds a local index by function name and orders patterns by selectivity.
func conflictSetTerms(seen []term.Term, body []term.Term) *data.HashSet[*term.Binding] {
	return conflictSet(seen, body,
		func(t term.Term) bool {
			if fn, err := term.AsFunction(t); err == nil && fn != nil && fn.Name != term.PairFunctionName {
				return true
			}
			return false
		},
		func(t term.Term) string {
			if fn, err := term.AsFunction(t); err == nil && fn != nil {
				return fn.Name
			}
			return ""
		},
		func(t term.Term) []term.Term {
			if fn, err := term.AsFunction(t); err == nil && fn != nil {
				return fn.Args
			}
			return nil
		},
	)
}
