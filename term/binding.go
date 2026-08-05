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
	"fmt"
	"sort"
	"strings"

	"github.com/specmon/specmon/utils"
)

// Binding maps Term keys to Term values. The public API is mutable
// (Set / Remove modify the receiver in place). The internal
// representation is an immutable HAMT: a logical mutation produces a
// new path-copied root and the wrapper swaps b.root to point at it.
// This lets BindingTrail.Mark snapshot the root pointer and
// Unwind restore it in O(1).
type Binding struct {
	root *hamtNode
	size int
}

// BindingTrail records (root, size) snapshots so a sequence of
// in-place updates to a Binding can be undone in one call. Mark
// pushes the current state; Unwind pops back to a mark.
type BindingTrail struct {
	snapshots []bindingSnapshot
}

type bindingSnapshot struct {
	root *hamtNode
	size int
}

// NewBindingTrail returns an empty trail.
func NewBindingTrail() *BindingTrail {
	return &BindingTrail{}
}

// NewBinding returns an empty binding. No HAMT node is allocated up
// front; the first Set creates one.
func NewBinding() *Binding {
	return &Binding{}
}

// BindingFromMap returns a binding initialised from m.
func BindingFromMap(m map[Term]Term) *Binding {
	b := &Binding{}
	for k, v := range m {
		b.Set(k, v)
	}
	return b
}

func (b *Binding) ComputeFixpoint() *Binding {
	c := b

	for {
		modified := false
		// Iterate over a snapshot of the current root so concurrent
		// Set inside the closure does not perturb iteration.
		startRoot := c.root
		startRoot.iterate(func(k, v Term) bool {
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
	if b.Size() != bp.Size() {
		return false
	}
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

// Get returns the value bound to k and whether k is present.
func (b *Binding) Get(k Term) (Term, bool) {
	if b == nil || b.root == nil {
		return nil, false
	}
	return b.root.get(k, k.Hash(), 0)
}

// Set associates k with v. Logically mutates the receiver in place; the
// underlying HAMT is path-copied and the receiver's root pointer is
// updated. The public API is mutable so existing callers don't change.
func (b *Binding) Set(k, v Term) {
	if b == nil {
		return
	}
	newRoot, added := b.root.set(k, v, k.Hash(), 0)
	if newRoot == b.root && !added {
		return
	}
	b.root = newRoot
	if added {
		b.size++
	}
}

// Remove drops the binding for k if present.
func (b *Binding) Remove(k Term) {
	if b == nil || b.root == nil {
		return
	}
	newRoot, removed := b.root.remove(k, k.Hash(), 0)
	if !removed {
		return
	}
	b.root = newRoot
	b.size--
}

func (b *Binding) Empty() bool {
	if b == nil {
		return true
	}
	return b.size == 0
}

func (b *Binding) Size() int {
	if b == nil {
		return 0
	}
	return b.size
}

// Iterate calls f(k, v) for each entry; iteration stops if f returns false.
// The order is HAMT-insertion-bitmap order, which is deterministic for a
// given sequence of inserts but not sorted by key.
func (b *Binding) Iterate(f func(Term, Term) bool) {
	if b == nil || b.root == nil {
		return
	}
	b.root.iterate(f)
}

// IterateSorted iterates entries in key string order.
func (b *Binding) IterateSorted(f func(Term, Term) bool) {
	if b == nil || b.root == nil {
		return
	}
	type kv struct {
		k Term
		v Term
	}
	entries := make([]kv, 0, b.size)
	b.root.iterate(func(k, v Term) bool {
		entries = append(entries, kv{k, v})
		return true
	})
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].k.String() < entries[j].k.String()
	})
	for _, e := range entries {
		if !f(e.k, e.v) {
			return
		}
	}
}

// Clone returns a binding with the same contents. Because the HAMT is
// immutable, this is an O(1) wrapper allocation: the new binding shares
// b.root and grows independently on subsequent Set/Remove.
func (b *Binding) Clone() *Binding {
	if b == nil {
		return &Binding{}
	}
	return &Binding{root: b.root, size: b.size}
}

// Extend returns a new binding containing every (k, v) pair from b
// updated with the (k, v) pairs from bp. On key conflict the value in
// bp wins ("rightmost wins"). The full path allocates one Binding
// wrapper plus the HAMT path-copies that bp's Set calls trigger; the
// original b and bp are not mutated.
//
// IMPORTANT ALIASING CONTRACT. Two fast paths return one of the inputs
// directly rather than allocating a fresh wrapper:
//
//   - bp.Empty()  -> returns b
//   - b.Empty()   -> returns bp
//
// This is a hot-path optimisation: empty-side merges are common in
// the conflictSet DFS, and the slow path would allocate one Binding
// per call. The trade-off is that callers MUST treat the result as
// immutable. A subsequent Set / Remove / SetWithTrail / MergeWithTrail
// on the returned *Binding will, in the fast-path case, mutate the
// input it aliases.
//
// In practice every call site in monitor / and rule / either:
//
//	(a) passes the result to Subst / Iterate / Hash (read-only), or
//	(b) feeds it back into another Extend (which respects the same
//	    contract because it allocates a new wrapper before any Set).
//
// If a caller ever needs an independently-mutable result, do
// b.Extend(bp).Clone() - Clone is O(1) and gives a fresh wrapper with
// its own root pointer.
func (b *Binding) Extend(bp *Binding) *Binding {
	if bp.Empty() {
		return b
	}
	if b.Empty() {
		return bp
	}
	out := &Binding{root: b.root, size: b.size}
	bp.Iterate(func(k, v Term) bool {
		out.Set(k, v)
		return true
	})
	return out
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

// Mark returns the index where the next snapshot will be recorded.
// Pass this value back to Unwind to restore the binding to its state
// at the call site. The snapshot itself is taken lazily by the next
// SetWithTrail or MergeWithTrail call on a Binding using this trail.
func (t *BindingTrail) Mark() int {
	if t == nil {
		return 0
	}
	return len(t.snapshots)
}

// SetWithTrail sets k=v. If trail is non-nil and the trail has fewer
// snapshots than the current depth implies, a snapshot of the
// pre-write (root, size) is appended so a later Unwind can restore.
// The trail parameter is retained for source compatibility with the
// previous entry-based trail.
func (b *Binding) SetWithTrail(k, v Term, trail *BindingTrail) {
	if trail != nil {
		trail.snapshots = append(trail.snapshots, bindingSnapshot{root: b.root, size: b.size})
	}
	b.Set(k, v)
}

// MergeWithTrail folds other into b in place, recording the pre-merge
// (root, size) once on trail so an enclosing Unwind restores the
// state from before the merge regardless of how many keys were set.
//
// MERGE SEMANTICS: "leftmost wins". A key already present in b keeps
// its existing value; the corresponding entry in other is skipped.
// This is the OPPOSITE of Extend, which lets the right-hand operand
// override.
//
// The divergence is intentional and tied to the single call site,
// the conflictSet DFS in monitor / (conflict_set.go). The DFS hands
// MergeWithTrail a delta produced by a unification against a pattern
// pre-substituted with the current accumulated binding b:
//
//	ps := p.Subst(b)        // pattern already carries b's keys
//	delta, _ := f.Unify(ps)
//	b.MergeWithTrail(delta, trail)
//
// Because the pattern was substituted with b before unification,
// any variable already bound in b appears as its substituted value
// (a constant or a sub-term) in ps. Unify therefore never produces a
// delta that re-binds an existing key of b; the "if present, skip"
// branch is a defensive no-op rather than a conflict-resolution
// policy. Future callers that violate this precondition would need
// Extend's "rightmost wins" behaviour and should use Extend
// (followed by Clone for an independent result) instead.
func (b *Binding) MergeWithTrail(other *Binding, trail *BindingTrail) {
	if other == nil || other.Empty() {
		return
	}
	if trail != nil {
		trail.snapshots = append(trail.snapshots, bindingSnapshot{root: b.root, size: b.size})
	}
	other.Iterate(func(k, v Term) bool {
		if _, ok := b.Get(k); ok {
			return true
		}
		b.Set(k, v)
		return true
	})
}

// Unwind restores the binding to the snapshot taken at index mark and
// discards trailing snapshots. With the HAMT representation this is a
// single (root, size) swap.
func (b *Binding) Unwind(trail *BindingTrail, mark int) {
	if trail == nil {
		return
	}
	if mark < 0 || mark >= len(trail.snapshots) {
		return
	}
	snap := trail.snapshots[mark]
	b.root = snap.root
	b.size = snap.size
	trail.snapshots = trail.snapshots[:mark]
}
