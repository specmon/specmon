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

package rule

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/specmon/specmon/term"
)

const (
	maxGeneratedNameLen = 30
)

// NameGenerator produces short, readable names for intermediate computation
// results during rule decomposition. Original variable and constant names
// are preserved as-is; only function application results are renamed.
//
// Generated names are guaranteed not to collide with any variable or function
// name already present in the rule.
type NameGenerator struct {
	funcAbbrev      map[string]string
	funcSeen        map[string]bool
	funcOrder       []string
	termOrder       []string
	termByKey       map[string]term.Term
	depthCache      map[string]int
	structuralCache map[string]string
	compactTerms    map[string]bool
	compactNext     map[string]int
	reserved        map[string]bool // names already in use (user + generated)
}

func NewNameGenerator(r *Rule) *NameGenerator {
	g := &NameGenerator{
		funcAbbrev:      make(map[string]string),
		funcSeen:        make(map[string]bool),
		termByKey:       make(map[string]term.Term),
		depthCache:      make(map[string]int),
		structuralCache: make(map[string]string),
		compactTerms:    make(map[string]bool),
		compactNext:     make(map[string]int),
		reserved:        make(map[string]bool),
	}

	g.collectRule(r)

	// Sort for deterministic output regardless of term walk order.
	slices.Sort(g.funcOrder)

	g.buildFuncAbbrev()
	g.buildStructuralNames()

	return g
}

func (g *NameGenerator) NameForTerm(t term.Term) string {
	switch v := t.(type) {
	case *term.Variable:
		return sanitizeName(v.Name)
	case *term.Constant[int], *term.Constant[string], *term.Constant[[]byte]:
		return sanitizeName(t.String())
	case *term.Function:
		return g.structuralName(v)
	}

	return sanitizeName(t.String())
}

func (g *NameGenerator) collectRule(r *Rule) {
	// Collect function names and terms for abbreviation/ref assignment.
	walkRuleTerms(r, false, func(t term.Term) {
		if v, ok := t.(*term.Function); ok {
			g.ensureFunc(v.Name)
			g.ensureTerm(v)
		}
	})

	// Collect all names already in use to prevent generated names from
	// colliding with user-defined variables or function names. Include
	// attributes so that variables in triggers/hints are covered.
	walkRuleTerms(r, true, func(t term.Term) {
		switch v := t.(type) {
		case *term.Variable:
			g.reserved[sanitizeName(v.Name)] = true
		case *term.Function:
			// Include function names — in spthy a bare token is ambiguous
			// between a variable and a nullary function.
			g.reserved[v.Name] = true
		}
	})
}

func (g *NameGenerator) ensureFunc(name string) {
	if g.funcSeen[name] {
		return
	}
	g.funcSeen[name] = true
	g.funcOrder = append(g.funcOrder, name)
}

func (g *NameGenerator) ensureTerm(t term.Term) {
	key := termKey(t)
	if _, ok := g.termByKey[key]; ok {
		return
	}
	g.termByKey[key] = t
	g.termOrder = append(g.termOrder, key)
}

func (g *NameGenerator) buildFuncAbbrev() {
	used := make(map[string]string)
	for _, name := range g.funcOrder {
		g.assignFuncAbbrev(name, used)
	}
}

func (g *NameGenerator) funcAbbrevFor(name string) string {
	if abbrev, ok := g.funcAbbrev[name]; ok {
		return abbrev
	}

	used := make(map[string]string, len(g.funcAbbrev))
	for funcName, abbrev := range g.funcAbbrev {
		used[abbrev] = funcName
	}

	return g.assignFuncAbbrev(name, used)
}

func (g *NameGenerator) assignFuncAbbrev(name string, used map[string]string) string {
	var abbrev string
	if len(name) <= 2 {
		abbrev = name
		if used[abbrev] != "" {
			abbrev = shortestUniquePrefix(name, used)
		}
	} else {
		abbrev = shortestUniquePrefix(name, used)
	}

	g.funcAbbrev[name] = abbrev
	used[abbrev] = name

	return abbrev
}

// buildStructuralNames pre-allocates structural names for all function terms in
// a deterministic order. Processing smaller depths first ensures that inner
// names are cached before outer names are computed. Within each depth level,
// terms are sorted by termKey so that suffix allocation via uniqueName is
// independent of RHS fact order.
func (g *NameGenerator) buildStructuralNames() {
	type entry struct {
		key   string
		depth int
	}

	entries := make([]entry, 0, len(g.termOrder))
	for _, key := range g.termOrder {
		t := g.termByKey[key]
		if _, ok := t.(*term.Function); ok {
			entries = append(entries, entry{key: key, depth: g.termDepth(t)})
		}
	}

	// Sort by depth first, then alphabetically by key for determinism.
	slices.SortFunc(entries, func(a, b entry) int {
		if c := cmp.Compare(a.depth, b.depth); c != 0 {
			return c
		}
		return cmp.Compare(a.key, b.key)
	})

	for _, e := range entries {
		g.structuralName(g.termByKey[e.key].(*term.Function))
	}
}

// uniqueName returns candidate if it is not yet reserved, otherwise appends
// a numeric suffix (_0, _1, ...) until a free name is found. The chosen name
// is added to the reserved set.
func (g *NameGenerator) uniqueName(candidate string) string {
	if !g.reserved[candidate] {
		g.reserved[candidate] = true
		return candidate
	}
	for i := 0; ; i++ {
		suffix := fmt.Sprintf("_%d", i)
		base := candidate
		if len(base)+len(suffix) > maxGeneratedNameLen {
			maxBaseLen := max(maxGeneratedNameLen-len(suffix), 1)
			if len(base) > maxBaseLen {
				base = strings.TrimRight(base[:maxBaseLen], "_")
				if base == "" {
					base = "x"
				}
			}
		}
		suffixed := base + suffix
		if !g.reserved[suffixed] {
			g.reserved[suffixed] = true
			return suffixed
		}
	}
}

func (g *NameGenerator) termDepth(t term.Term) int {
	key := termKey(t)
	if depth, ok := g.depthCache[key]; ok {
		return depth
	}

	f, ok := t.(*term.Function)
	if !ok {
		g.depthCache[key] = 0
		return 0
	}

	maxDepth := 0
	for _, arg := range f.Args {
		if arg == nil {
			continue
		}
		maxDepth = max(maxDepth, g.termDepth(arg))
	}
	depth := maxDepth + 1
	g.depthCache[key] = depth
	return depth
}

func (g *NameGenerator) structuralName(f *term.Function) string {
	key := termKey(f)
	if name, ok := g.structuralCache[key]; ok {
		return name
	}

	abbrev := g.funcAbbrevFor(f.Name)

	if len(f.Args) == 0 {
		name := g.uniqueName(abbrev)
		g.structuralCache[key] = name
		return name
	}

	parts := make([]string, 0, len(f.Args)+1)
	parts = append(parts, abbrev)
	needsCompact := false
	for _, arg := range f.Args {
		parts = append(parts, g.NameForTerm(arg))
		if argFunc, ok := arg.(*term.Function); ok && g.compactTerms[termKey(argFunc)] {
			needsCompact = true
		}
	}

	name := strings.Join(parts, "_")
	if len(name) > maxGeneratedNameLen || needsCompact {
		name = g.nextCompactName(abbrev)
		g.compactTerms[key] = true
	} else {
		name = g.uniqueName(name)
	}
	g.structuralCache[key] = name
	return name
}

func (g *NameGenerator) nextCompactName(abbrev string) string {
	// Cap the abbreviation so that abbrev + digit always fits within the limit.
	// This handles pathological cases where two long function names share a
	// long common prefix, producing a lengthy abbreviation.
	maxAbbrevLen := max(maxGeneratedNameLen-1, 1) // leave room for at least one digit
	if len(abbrev) > maxAbbrevLen {
		abbrev = abbrev[:maxAbbrevLen]
	}

	for {
		index := g.compactNext[abbrev]
		g.compactNext[abbrev] = index + 1
		candidate := fmt.Sprintf("%s%d", abbrev, index)
		if len(candidate) > maxGeneratedNameLen {
			// The index itself grew too large for the abbreviation; trim further.
			trimLen := max(maxGeneratedNameLen-len(fmt.Sprintf("%d", index)), 1)
			candidate = fmt.Sprintf("%s%d", abbrev[:trimLen], index)
		}
		if !g.reserved[candidate] {
			g.reserved[candidate] = true
			return candidate
		}
	}
}

// shortestUniquePrefix returns the shortest prefix of name that is not already
// in used.
func shortestUniquePrefix(name string, used map[string]string) string {
	for i := 1; i <= len(name); i++ {
		candidate := name[:i]
		if used[candidate] == "" {
			return candidate
		}
	}
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s%d", name, i)
		if used[candidate] == "" {
			return candidate
		}
	}
}

// sanitizeName strips Tamarin variable prefixes ($, ~) and keeps only
// characters valid in identifier names: [a-zA-Z0-9_].
func sanitizeName(s string) string {
	// Strip leading $ and ~ prefixes.
	s = strings.TrimLeft(s, "$~")

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

// termKey returns a string key for a term that is unique across types.
// Prepending the type prevents cross-type collisions (e.g. a variable
// named "f(x)" vs a function f(x)).
func termKey(t term.Term) string {
	if t == nil {
		panic("termKey: nil term")
	}
	return t.GetType() + ":" + t.String()
}

func walkRuleTerms(r *Rule, includeAttrs bool, visit func(term.Term)) {
	if r == nil {
		return
	}

	facts := make([]*Fact, 0, len(r.LHS)+len(r.Act)+len(r.RHS))
	facts = append(facts, r.LHS...)
	facts = append(facts, r.Act...)
	facts = append(facts, r.RHS...)

	for _, f := range facts {
		for _, arg := range f.Args {
			walkTerm(arg, visit)
		}
	}

	if includeAttrs {
		for _, t := range r.Triggers() {
			walkTerm(t, visit)
		}
		for _, t := range r.Hints() {
			walkTerm(t, visit)
		}
	}
}

func walkTerm(t term.Term, visit func(term.Term)) {
	if t == nil {
		return
	}
	visit(t)
	f, ok := t.(*term.Function)
	if !ok {
		return
	}
	for _, arg := range f.Args {
		walkTerm(arg, visit)
	}
}
