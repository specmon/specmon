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

package term_test

import (
	"testing"

	"github.com/specmon/specmon/term"
)

// bindingSnapshot returns the binding's contents as a map for
// deep-equal comparison in tests.
func bindingSnapshot(b *term.Binding) map[string]string {
	out := map[string]string{}
	b.Iterate(func(k, v term.Term) bool {
		out[k.String()] = v.String()
		return true
	})
	return out
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestBindingTrailSetUnwindRoundtrip is the basic Mark/Unwind contract:
// a single Set followed by Unwind returns the binding to its pre-Set
// state.
func TestBindingTrailSetUnwindRoundtrip(t *testing.T) {
	b := term.NewBinding()
	b.Set(term.NewVariable("a"), term.NewConstant("1"))
	before := bindingSnapshot(b)

	trail := term.NewBindingTrail()
	mark := trail.Mark()

	b.SetWithTrail(term.NewVariable("b"), term.NewConstant("2"), trail)
	if v, ok := b.Get(term.NewVariable("b")); !ok || v.String() != "'2'" {
		t.Fatalf("post-Set state wrong: got %v %v", v, ok)
	}

	b.Unwind(trail, mark)
	if got := bindingSnapshot(b); !mapsEqual(got, before) {
		t.Errorf("Unwind did not restore pre-Set state: got %v, want %v", got, before)
	}
}

// TestBindingTrailMergeUnwindRoundtrip covers MergeWithTrail: merging
// in a multi-key other followed by Unwind restores the binding
// regardless of how many keys were added.
func TestBindingTrailMergeUnwindRoundtrip(t *testing.T) {
	b := term.NewBinding()
	b.Set(term.NewVariable("a"), term.NewConstant("1"))
	before := bindingSnapshot(b)

	other := term.NewBinding()
	other.Set(term.NewVariable("b"), term.NewConstant("2"))
	other.Set(term.NewVariable("c"), term.NewConstant("3"))
	other.Set(term.NewVariable("d"), term.NewConstant("4"))

	trail := term.NewBindingTrail()
	mark := trail.Mark()

	b.MergeWithTrail(other, trail)
	if b.Size() != 4 {
		t.Fatalf("post-merge size wrong: got %d, want 4", b.Size())
	}

	b.Unwind(trail, mark)
	if got := bindingSnapshot(b); !mapsEqual(got, before) {
		t.Errorf("Unwind did not restore pre-merge state: got %v, want %v", got, before)
	}
}

// TestBindingTrailNestedMarks covers the DFS pattern used by
// conflictSet: push mark, mutate, recurse (push another mark,
// mutate, unwind), unwind to outer mark. Each unwind level must
// restore exactly what existed at that mark.
func TestBindingTrailNestedMarks(t *testing.T) {
	b := term.NewBinding()
	b.Set(term.NewVariable("a"), term.NewConstant("1"))
	s0 := bindingSnapshot(b)

	trail := term.NewBindingTrail()
	outerMark := trail.Mark()
	b.SetWithTrail(term.NewVariable("b"), term.NewConstant("2"), trail)
	s1 := bindingSnapshot(b)

	innerMark := trail.Mark()
	b.SetWithTrail(term.NewVariable("c"), term.NewConstant("3"), trail)
	b.SetWithTrail(term.NewVariable("d"), term.NewConstant("4"), trail)
	if b.Size() != 4 {
		t.Fatalf("inner size wrong: got %d, want 4", b.Size())
	}

	// Unwind inner: back to s1.
	b.Unwind(trail, innerMark)
	if got := bindingSnapshot(b); !mapsEqual(got, s1) {
		t.Errorf("inner Unwind: got %v, want %v", got, s1)
	}

	// Unwind outer: back to s0.
	b.Unwind(trail, outerMark)
	if got := bindingSnapshot(b); !mapsEqual(got, s0) {
		t.Errorf("outer Unwind: got %v, want %v", got, s0)
	}
}

// TestBindingTrailUnwindClearsTrail confirms the trail is truncated
// after Unwind so subsequent Mark/Unwind cycles do not pick up stale
// snapshots.
func TestBindingTrailUnwindClearsTrail(t *testing.T) {
	b := term.NewBinding()
	trail := term.NewBindingTrail()

	mark1 := trail.Mark()
	b.SetWithTrail(term.NewVariable("a"), term.NewConstant("1"), trail)
	b.Unwind(trail, mark1)

	// After unwinding, the next Mark should be at the cleared trail
	// position. A second cycle must work the same.
	mark2 := trail.Mark()
	if mark2 != 0 {
		t.Errorf("Mark after Unwind: got %d, want 0 (trail should be reset)", mark2)
	}
	b.SetWithTrail(term.NewVariable("b"), term.NewConstant("2"), trail)
	if v, ok := b.Get(term.NewVariable("b")); !ok || v.String() != "'2'" {
		t.Fatalf("post-second-cycle Set state wrong: got %v %v", v, ok)
	}
	b.Unwind(trail, mark2)
	if !b.Empty() {
		t.Errorf("second-cycle Unwind did not empty the binding: %v", bindingSnapshot(b))
	}
}

// TestBindingTrailMergeWithExistingKey verifies the documented
// "leftmost wins" semantics of MergeWithTrail: a key already in b is
// NOT overwritten by other.
func TestBindingTrailMergeWithExistingKey(t *testing.T) {
	b := term.NewBinding()
	b.Set(term.NewVariable("x"), term.NewConstant("original"))

	other := term.NewBinding()
	other.Set(term.NewVariable("x"), term.NewConstant("override"))
	other.Set(term.NewVariable("y"), term.NewConstant("new"))

	trail := term.NewBindingTrail()
	b.MergeWithTrail(other, trail)

	xVal, _ := b.Get(term.NewVariable("x"))
	if xVal.String() != "'original'" {
		t.Errorf("MergeWithTrail must keep b's existing value (leftmost wins): got %v", xVal)
	}
	yVal, ok := b.Get(term.NewVariable("y"))
	if !ok || yVal.String() != "'new'" {
		t.Errorf("MergeWithTrail must add absent keys from other: got %v %v", yVal, ok)
	}
}

// TestBindingTrailNoOpOnEmpty covers the trail no-op paths: merging
// nil or an empty other does nothing and does not push a snapshot.
func TestBindingTrailNoOpOnEmpty(t *testing.T) {
	b := term.NewBinding()
	b.Set(term.NewVariable("a"), term.NewConstant("1"))
	before := bindingSnapshot(b)

	trail := term.NewBindingTrail()
	markBefore := trail.Mark()

	b.MergeWithTrail(nil, trail)
	b.MergeWithTrail(term.NewBinding(), trail)

	if got := bindingSnapshot(b); !mapsEqual(got, before) {
		t.Errorf("MergeWithTrail(empty) changed b: got %v, want %v", got, before)
	}
	if got := trail.Mark(); got != markBefore {
		t.Errorf("MergeWithTrail(empty) pushed a snapshot: mark went from %d to %d", markBefore, got)
	}
}
