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

package term

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/utils"
)

type Binding struct {
	m *data.HashMap[Term, Term]
}

// BindingTrail records inverse Set/Remove operations so a sequence of
// in-place updates to a Binding can be undone in one call. It enables
// backtracking DFS over a single mutable binding instead of cloning
// the binding at every branch.
type BindingTrail struct {
	entries []bindingTrailEntry
}

type bindingTrailEntry struct {
	key     Term
	old     Term
	existed bool
}

// NewBindingTrail returns an empty trail.
func NewBindingTrail() *BindingTrail {
	return &BindingTrail{}
}

func NewBinding() *Binding {
	return &Binding{
		m: data.NewHashMap[Term, Term](),
	}
}

func BindingFromMap(m map[Term]Term) *Binding {
	n := data.NewHashMap[Term, Term]()

	for k, v := range m {
		n.Set(k, v)
	}

	return &Binding{n}
}

func (b *Binding) ComputeFixpoint() *Binding {
	c := b

	for {
		modified := false
		c.Iterate(func(k, v Term) bool {
			if n := v.Subst(b); !n.Equal(v) {
				c.Set(k, n)
				modified = true
			}

			return true
		})
		if !modified {
			break
		}
	}

	return c
}

func (b *Binding) Equal(bp *Binding) bool {
	equal := true

	b.Iterate(func(k, v Term) bool {
		if vp, ok := bp.Get(k); ok {
			if !v.Equal(vp) {
				equal = false

				return false
			}
		} else {
			equal = false

			return false
		}

		return true
	})

	return equal
}

func (b *Binding) String() string {
	var s string

	b.IterateSorted(func(k, v Term) bool {
		s += fmt.Sprintf("%s -> %s, ", k, v)

		return true
	})
	s = strings.TrimSuffix(s, ", ")

	return fmt.Sprintf("[ %s ]", s)
}

func (b *Binding) Compatible(bp *Binding) bool {
	compatible := true

	b.Iterate(func(k, v Term) bool {
		if vp, ok := bp.Get(k); ok {
			if !v.Equal(vp) {
				compatible = false

				return false
			}
		}

		return true
	})

	return compatible
}

func (b *Binding) Self() *Binding {
	return b
}

func (b *Binding) Hash() uint64 {
	h := fnv.New64a()

	b.IterateSorted(func(k, v Term) bool {
		var buf [8]byte

		binary.LittleEndian.PutUint64(buf[:], k.Hash())
		h.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], v.Hash())
		h.Write(buf[:])

		return true
	})

	return h.Sum64()
}

// Wrapper functions for HashMap.

func (b *Binding) Get(k Term) (Term, bool) {
	return b.m.Get(k)
}

func (b *Binding) Set(k, v Term) {
	b.m.Set(k, v)
}

func (b *Binding) Remove(k Term) {
	b.m.Remove(k)
}

func (b *Binding) Empty() bool {
	return b.m.Empty()
}

func (b *Binding) Size() int {
	return b.m.Size()
}

func (b *Binding) Iterate(f func(Term, Term) bool) {
	b.m.Iterate(f)
}

func (b *Binding) IterateSorted(f func(Term, Term) bool) {
	b.m.IterateSorted(f)
}

func (b *Binding) Clone() *Binding {
	return &Binding{b.m.Clone()}
}

func (b *Binding) Extend(bp *Binding) *Binding {
	return &Binding{b.m.Extend(bp.m)}
}

// HashUnordered returns an order-independent hash of (k, v) pairs using XOR.
// Use for deduplication where collisions are handled by Equal().
// Cheaper than Hash() because it does not iterate sorted.
func (b *Binding) HashUnordered() uint64 {
	if b == nil || b.Empty() {
		return 0
	}
	var h uint64
	b.Iterate(func(k, v Term) bool {
		// Mix key and value hashes, then XOR into the accumulator.
		pair := utils.FNV64aUint64(k.Hash(), v.Hash())
		h ^= pair
		return true
	})
	return h
}

// Mark returns the current trail length so callers can Unwind back to this point.
func (t *BindingTrail) Mark() int {
	if t == nil {
		return 0
	}
	return len(t.entries)
}

// SetWithTrail records the previous value (if any) at k before setting it to v.
// When v equals the existing value the binding is left untouched and no trail
// entry is appended.
func (b *Binding) SetWithTrail(k, v Term, trail *BindingTrail) {
	if trail == nil {
		b.Set(k, v)
		return
	}
	if old, ok := b.Get(k); ok {
		if !old.Equal(v) {
			trail.entries = append(trail.entries, bindingTrailEntry{
				key:     k,
				old:     old,
				existed: true,
			})
			b.Set(k, v)
		}
		return
	}
	trail.entries = append(trail.entries, bindingTrailEntry{
		key:     k,
		existed: false,
	})
	b.Set(k, v)
}

// MergeWithTrail sets keys from other that are not already present in b, each
// recorded on the trail so Unwind can restore the pre-merge state.
func (b *Binding) MergeWithTrail(other *Binding, trail *BindingTrail) {
	if other == nil || other.Empty() {
		return
	}
	other.Iterate(func(k, v Term) bool {
		if _, ok := b.Get(k); ok {
			return true
		}
		b.SetWithTrail(k, v, trail)
		return true
	})
}

// Unwind rolls back trail entries after mark, restoring the binding to its
// state at the matching Mark() call.
func (b *Binding) Unwind(trail *BindingTrail, mark int) {
	if trail == nil {
		return
	}
	if mark < 0 || mark > len(trail.entries) {
		mark = 0
	}
	for i := len(trail.entries) - 1; i >= mark; i-- {
		entry := trail.entries[i]
		if entry.existed {
			b.Set(entry.key, entry.old)
			continue
		}
		b.Remove(entry.key)
	}
	trail.entries = trail.entries[:mark]
}
