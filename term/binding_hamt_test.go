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
	"fmt"
	"testing"

	"github.com/specmon/specmon/term"
)

// The HAMT inside Binding is package-internal; these tests exercise it
// through the public Binding API at sizes large enough to stress the
// node-splitting and collision paths.

// TestBindingHAMTLargeInsertGet inserts many distinct variables and
// verifies each Get returns the inserted value. HAMTs split internal
// nodes once enough keys share a hash-bit prefix; this test crosses
// the typical split threshold.
func TestBindingHAMTLargeInsertGet(t *testing.T) {
	b := term.NewBinding()
	const N = 512
	for i := 0; i < N; i++ {
		b.Set(term.NewVariable(fmt.Sprintf("v%d", i)), term.NewConstant(i))
	}
	if b.Size() != N {
		t.Fatalf("Size: got %d, want %d", b.Size(), N)
	}
	for i := 0; i < N; i++ {
		v, ok := b.Get(term.NewVariable(fmt.Sprintf("v%d", i)))
		if !ok {
			t.Errorf("Get(v%d): miss", i)
			continue
		}
		c, err := term.AsConstant[int](v)
		if err != nil {
			t.Errorf("Get(v%d) returned non-int constant: %v", i, v)
			continue
		}
		if c.Value != i {
			t.Errorf("Get(v%d) = %d, want %d", i, c.Value, i)
		}
	}
}

// TestBindingHAMTOverwriteSameKey verifies Set with an existing key
// replaces the value and does not grow the size.
func TestBindingHAMTOverwriteSameKey(t *testing.T) {
	b := term.NewBinding()
	x := term.NewVariable("x")
	b.Set(x, term.NewConstant(1))
	if b.Size() != 1 {
		t.Fatalf("Size after first Set: got %d, want 1", b.Size())
	}
	b.Set(x, term.NewConstant(2))
	if b.Size() != 1 {
		t.Fatalf("Size after overwrite: got %d, want 1", b.Size())
	}
	v, _ := b.Get(x)
	c, _ := term.AsConstant[int](v)
	if c.Value != 2 {
		t.Errorf("Get after overwrite: got %d, want 2", c.Value)
	}
}

// TestBindingHAMTRemove verifies Remove drops the entry and Get misses
// afterwards. Tests the inverse of Set on the HAMT.
func TestBindingHAMTRemove(t *testing.T) {
	b := term.NewBinding()
	const N = 64
	for i := 0; i < N; i++ {
		b.Set(term.NewVariable(fmt.Sprintf("v%d", i)), term.NewConstant(i))
	}
	// Remove every odd entry.
	for i := 1; i < N; i += 2 {
		b.Remove(term.NewVariable(fmt.Sprintf("v%d", i)))
	}
	want := N / 2
	if b.Size() != want {
		t.Fatalf("Size after Remove: got %d, want %d", b.Size(), want)
	}
	for i := 0; i < N; i++ {
		_, ok := b.Get(term.NewVariable(fmt.Sprintf("v%d", i)))
		if i%2 == 0 && !ok {
			t.Errorf("v%d should still be present", i)
		}
		if i%2 == 1 && ok {
			t.Errorf("v%d should be removed", i)
		}
	}
}

// TestBindingHAMTCloneIndependence verifies that Clone'ing the binding
// yields an independent wrapper: mutations on the clone do not affect
// the source's contents, even though they share the HAMT root pointer
// (HAMT mutations are path-copying).
func TestBindingHAMTCloneIndependence(t *testing.T) {
	src := term.NewBinding()
	for i := 0; i < 16; i++ {
		src.Set(term.NewVariable(fmt.Sprintf("v%d", i)), term.NewConstant(i))
	}
	srcSize := src.Size()

	clone := src.Clone()
	if clone.Size() != srcSize {
		t.Fatalf("Clone Size mismatch: got %d, want %d", clone.Size(), srcSize)
	}

	// Mutate the clone: add a new key, overwrite an existing key,
	// remove an existing key.
	clone.Set(term.NewVariable("new"), term.NewConstant(999))
	clone.Set(term.NewVariable("v0"), term.NewConstant(-1))
	clone.Remove(term.NewVariable("v5"))

	if src.Size() != srcSize {
		t.Errorf("source Size changed: got %d, want %d", src.Size(), srcSize)
	}
	if _, ok := src.Get(term.NewVariable("new")); ok {
		t.Errorf("clone's new key leaked to source")
	}
	v0, _ := src.Get(term.NewVariable("v0"))
	c0, _ := term.AsConstant[int](v0)
	if c0.Value != 0 {
		t.Errorf("source v0 changed: got %d, want 0", c0.Value)
	}
	if _, ok := src.Get(term.NewVariable("v5")); !ok {
		t.Errorf("source v5 removed by clone's Remove")
	}
}

// TestBindingHAMTIterateAll covers Iterate visiting every entry once.
// HAMT iteration order is bitmap order, not insertion order; we test
// completeness, not order.
func TestBindingHAMTIterateAll(t *testing.T) {
	b := term.NewBinding()
	const N = 100
	want := map[string]int{}
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("v%d", i)
		b.Set(term.NewVariable(name), term.NewConstant(i))
		want[name] = i
	}
	got := map[string]int{}
	b.Iterate(func(k, v term.Term) bool {
		c, _ := term.AsConstant[int](v)
		got[k.String()] = c.Value
		return true
	})
	if len(got) != len(want) {
		t.Fatalf("Iterate visited %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("Iterate(%s) = %d, want %d", k, got[k], v)
		}
	}
}

// TestBindingHAMTEmptyAfterAllRemoved verifies Empty/Size after a full
// Remove cycle.
func TestBindingHAMTEmptyAfterAllRemoved(t *testing.T) {
	b := term.NewBinding()
	const N = 32
	for i := 0; i < N; i++ {
		b.Set(term.NewVariable(fmt.Sprintf("v%d", i)), term.NewConstant(i))
	}
	for i := 0; i < N; i++ {
		b.Remove(term.NewVariable(fmt.Sprintf("v%d", i)))
	}
	if !b.Empty() {
		t.Errorf("Empty after all-Remove: got %d entries", b.Size())
	}
}
