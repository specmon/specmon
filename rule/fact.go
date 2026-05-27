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
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"

	"github.com/specmon/specmon/term"
)

type FactType string

const (
	LinearFact     = FactType("linear")
	PersistentFact = FactType("persistent")
)

var ErrFactUnify = errors.New("cannot unify facts")

type Fact struct {
	Name string      `json:"name"`
	Args []term.Term `json:"arguments"`
	Type FactType    `json:"type"`
}

func NewFact(name string, args []term.Term, t FactType) *Fact {
	return &Fact{
		Name: name,
		Args: args,
		Type: t,
	}
}

func (f *Fact) IsLinear() bool {
	return f.Type == LinearFact
}

func (f *Fact) IsPersistent() bool {
	return f.Type == PersistentFact
}

func (f *Fact) String() string {
	var args string

	for _, a := range f.Args {
		args += fmt.Sprintf("%s, ", a)
	}
	args = strings.TrimSuffix(args, ", ")

	if f.IsPersistent() {
		return fmt.Sprintf("!%s(%s)", f.Name, args)
	}

	return fmt.Sprintf("%s(%s)", f.Name, args)
}

func (f *Fact) Equal(f1 *Fact) bool {
	if f.Name != f1.Name {
		return false
	}

	if len(f.Args) != len(f1.Args) {
		return false
	}

	for i, a := range f.Args {
		if !a.Equal(f1.Args[i]) {
			return false
		}
	}

	return true
}

func (f *Fact) Hash() uint64 {
	h := fnv.New64a()
	h.Write([]byte(f.Name))
	h.Write([]byte(f.Type))

	for _, arg := range f.Args {
		hash := arg.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	return h.Sum64()
}

func (f *Fact) Unify(other *Fact) (*term.Binding, error) {
	if f.Name != other.Name {
		// return nil, fmt.Errorf("cannot unify %s and %s", f.Name, other.Name)
		return nil, ErrFactUnify
	}

	if len(f.Args) != len(other.Args) {
		// return nil, fmt.Errorf("cannot unify %s and %s", f, other)
		return nil, ErrFactUnify
	}

	// Optimization: collect all non-empty partial bindings to avoid repeated Extend() operations
	// Skip empty bindings since they don't contribute anything
	var partials []*term.Binding

	for i, a := range f.Args {
		b1, err := a.Unify(other.Args[i])
		if err != nil {
			// return nil, fmt.Errorf("cannot unify %s and %s: %w", f, other, err)
			return nil, ErrFactUnify
		}
		// Only collect non-empty bindings
		if b1.Size() > 0 {
			partials = append(partials, b1)
		}
	}

	// Fast path: if no bindings were created, return empty binding
	if len(partials) == 0 {
		return term.NewBinding(), nil
	}

	// Now merge all bindings at once
	b := term.NewBinding()
	for _, partial := range partials {
		b = b.Extend(partial)
	}

	return b, nil
}

func (f *Fact) Subst(b *term.Binding) *Fact {
	g := NewFact(f.Name, make([]term.Term, len(f.Args)), f.Type)

	for i, a := range f.Args {
		g.Args[i] = a.Subst(b)
	}

	return g
}

func (f *Fact) Vars() []*term.Variable {
	total := 0
	for _, a := range f.Args {
		total += term.VarCount(a)
	}
	if total == 0 {
		return nil
	}
	vars := make([]*term.Variable, 0, total)
	for _, a := range f.Args {
		vars = term.AppendVars(vars, a)
	}
	return vars
}

func (f *Fact) IsGround() bool {
	for _, a := range f.Args {
		if !term.IsGround(a) {
			return false
		}
	}

	return true
}

func (f *Fact) ReplaceFormats() *Fact {
	g := NewFact(f.Name, make([]term.Term, len(f.Args)), f.Type)

	for i, a := range f.Args {
		g.Args[i] = term.ReplaceFormats(a)
	}

	return g
}

func (f *Fact) HasFunctions() bool {
	for _, a := range f.Args {
		if a.GetType() == term.FunctionType {
			return true
		}
	}

	return false
}

type Facts []*Fact

func (f Facts) Len() int {
	return len(f)
}

func (f Facts) Less(i, j int) bool {
	return f[i].String() < f[j].String()
}

func (f Facts) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

func (f Facts) Vars() []*term.Variable {
	total := 0
	for _, fact := range f {
		for _, arg := range fact.Args {
			total += term.VarCount(arg)
		}
	}
	if total == 0 {
		return nil
	}
	vars := make([]*term.Variable, 0, total)
	for _, fact := range f {
		for _, arg := range fact.Args {
			vars = term.AppendVars(vars, arg)
		}
	}
	return vars
}

func (f Facts) HasFunctions() bool {
	for _, fact := range f {
		if fact.HasFunctions() {
			return true
		}
	}

	return false
}

func (f Facts) ExpandFacts(b *term.Binding) []*Fact {
	// FIX: Make this more efficient.
	newFacts := make([]*Fact, len(f))
	for i, fact := range f {
		newFact := NewFact(fact.Name, slices.Clone(fact.Args), fact.Type)
		for j := range newFact.Args {
			b.Iterate(func(k, v term.Term) bool {
				newFact.Args[j] = term.UnifyReplaceRecursive(newFact.Args[j], k, v)

				return true
			})
		}
		newFacts[i] = newFact
	}

	return newFacts
}
