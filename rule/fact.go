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

package rule

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/specmon/specmon/term"
)

type FactType string

const (
	LinearFact     = FactType("linear")
	PersistentFact = FactType("persistent")

	ComputeFactName = "Compute_"
)

var ErrFactUnify = errors.New("cannot unify facts")

type Fact struct {
	Name string      `json:"name"`
	Args []term.Term `json:"arguments"`
	Type FactType    `json:"type"`

	// hashCache memoises Hash(). 0 is the uncomputed sentinel; if the
	// FNV-1a digest of (Name, Type, args) genuinely lands on 0 the next
	// call re-walks and re-stores - idempotent and very rare.
	//
	// atomic.Uint64 is the synchronisation primitive: concurrent Hash()
	// callers race on Load/Store but the value they compute is the same,
	// so the last Store overwrites with an identical value. The race
	// detector accepts atomic operations as properly synchronised.
	hashCache atomic.Uint64
}

func NewFact(name string, args []term.Term, t FactType) *Fact {
	return &Fact{
		Name: name,
		Args: args,
		Type: t,
	}
}

// IsInternalFactName reports whether name marks a fact that is never stored.
func IsInternalFactName(name string) bool {
	return strings.HasSuffix(name, "_")
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

// Hash returns a 64-bit FNV-1a digest of (Name, Type, args). The result
// is memoised in hashCache via atomic ops so concurrent callers do not
// race on the cache slot; see the field comment for the sentinel
// strategy.
//
// Unlike the term-level Hash methods (Constant, Variable, Function in
// term/term.go) which recompute on every call to keep terms trivially
// race-free, Fact carries an atomic cache because each Fact is hashed
// many times per ProcessEvent: once per Config.Hash, once per
// conflictSet bucket dedup, once per bindingSet.Add. Removing this
// cache regresses signal-large from ~2.3s to ~17s on the 20k trace.
func (f *Fact) Hash() uint64 {
	if h := f.hashCache.Load(); h != 0 {
		return h
	}

	h := fnv.New64a()
	h.Write([]byte(f.Name))
	h.Write([]byte(f.Type))

	for _, arg := range f.Args {
		hash := arg.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	sum := h.Sum64()
	if sum == 0 {
		// Reserve 0 as the uncomputed sentinel; the next call will
		// re-walk and re-store. Mathematically possible but extremely
		// rare.
		return 0
	}
	f.hashCache.Store(sum)
	return sum
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
			if errors.Is(err, term.ErrEvaluation) {
				return nil, fmt.Errorf("%w: %w", ErrFactUnify, err)
			}
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
	args := make([]term.Term, len(f.Args))
	for i, a := range f.Args {
		args[i] = a.Subst(b)
	}

	return NewFact(f.Name, args, f.Type)
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

func (f *Fact) ReplaceFormats() (*Fact, error) {
	args := make([]term.Term, len(f.Args))
	for i, a := range f.Args {
		var err error
		args[i], err = term.ReplaceFormats(a)
		if err != nil {
			return nil, fmt.Errorf("replace formats in fact %s argument %d: %w", f.Name, i, err)
		}
	}

	return NewFact(f.Name, args, f.Type), nil
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

// ExpandFacts expands the macros of b, which maps the head of each macro to
// its body, in the arguments of the facts.
func (f Facts) ExpandFacts(b *term.Binding) []*Fact {
	newFacts := make([]*Fact, len(f))
	for i, fact := range f {
		args := slices.Clone(fact.Args)
		for j := range args {
			b.Iterate(func(k, v term.Term) bool {
				if head, ok := k.(*term.Function); ok {
					args[j] = expandMacro(args[j], head, v)
				}

				return true
			})
		}
		newFacts[i] = NewFact(fact.Name, args, fact.Type)
	}

	return newFacts
}

// expandMacro replaces every application of the macro with the given head
// in t by its body, with the parameters of the head, distinct variables,
// replaced by the arguments of the application. Only the parameters are
// substituted. A variable of the body that is not a parameter keeps its name.
func expandMacro(t term.Term, head *term.Function, body term.Term) term.Term {
	f, ok := t.(*term.Function)
	if !ok {
		return t
	}
	args := make([]term.Term, len(f.Args))
	for i, arg := range f.Args {
		args[i] = expandMacro(arg, head, body)
	}
	if f.Name != head.Name || len(args) != len(head.Args) {
		return term.NewFunction(f.Name, args)
	}
	parameters := term.NewBinding()
	for i, parameter := range head.Args {
		parameters.Set(parameter, args[i])
	}
	return term.SubstBinding(parameters, body)
}

// RewriteTerm returns the sole argument of a rewrite action, or nil for
// other actions. The caller validates the emitted event's shape.
func (f *Fact) RewriteTerm() term.Term {
	if f.Name == RewriteEventName && len(f.Args) == 1 {
		return f.Args[0]
	}
	return nil
}
