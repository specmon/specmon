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

package data_test

import (
	"slices"
	"testing"

	"github.com/specmon/specmon/data"
)

func TestHashMap(t *testing.T) {
	t.Parallel()

	h := data.NewHashMap[[]int, []int]()

	if !h.Empty() {
		t.Errorf("%v should be empty", h)
	}

	h.Set([]int{1, 2, 3}, []int{4, 5, 6})

	v, ok := h.Get([]int{1, 2, 3})
	if !ok || slices.Compare(v, []int{4, 5, 6}) != 0 {
		t.Errorf("%v should contain %d", h, 1)
	}

	if h.Size() != 1 {
		t.Errorf("%v should have size of %d, got %d", h, 1, h.Size())
	}

	h.Remove([]int{1, 2, 3})

	if !h.Empty() {
		t.Errorf("%v should be empty", h)
	}
}

// collidingKey forces a hash collision between distinct values via the
// HashMap's Hasher interface. Without bucket-per-hash storage, the second
// Set would overwrite the first; both entries would resolve to the same
// pair on subsequent Get calls.
type collidingKey struct {
	id     int
	bucket uint64
}

func (k collidingKey) Hash() uint64 { return k.bucket }

func (k collidingKey) Equal(other collidingKey) bool { return k.id == other.id }

func TestForcedCollisionDoesNotOverwrite(t *testing.T) {
	t.Parallel()

	h := data.NewHashMap[collidingKey, string]()

	k1 := collidingKey{id: 1, bucket: 42}
	k2 := collidingKey{id: 2, bucket: 42}
	k3 := collidingKey{id: 3, bucket: 42}

	h.Set(k1, "one")
	h.Set(k2, "two")
	h.Set(k3, "three")

	if h.Size() != 3 {
		t.Fatalf("Size() = %d; want 3 (all three colliding keys stored)", h.Size())
	}

	for _, tc := range []struct {
		k    collidingKey
		want string
	}{
		{k1, "one"},
		{k2, "two"},
		{k3, "three"},
	} {
		got, ok := h.Get(tc.k)
		if !ok {
			t.Errorf("Get(%+v) = (_, false); want (%q, true)", tc.k, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("Get(%+v) = %q; want %q", tc.k, got, tc.want)
		}
	}

	// Update of one colliding key must not corrupt the others.
	h.Set(k2, "two-updated")
	if got, _ := h.Get(k2); got != "two-updated" {
		t.Errorf("Get(k2 after Set) = %q; want %q", got, "two-updated")
	}
	if got, _ := h.Get(k1); got != "one" {
		t.Errorf("Get(k1 after k2 update) = %q; want %q (sibling corrupted)", got, "one")
	}
	if got, _ := h.Get(k3); got != "three" {
		t.Errorf("Get(k3 after k2 update) = %q; want %q (sibling corrupted)", got, "three")
	}

	// Remove must not affect siblings.
	h.Remove(k2)
	if _, ok := h.Get(k2); ok {
		t.Error("Get(k2 after Remove) returned (true); want (false)")
	}
	if got, _ := h.Get(k1); got != "one" {
		t.Errorf("Get(k1 after Remove(k2)) = %q; want %q", got, "one")
	}
	if got, _ := h.Get(k3); got != "three" {
		t.Errorf("Get(k3 after Remove(k2)) = %q; want %q", got, "three")
	}
	if h.Size() != 2 {
		t.Errorf("Size() after Remove = %d; want 2", h.Size())
	}
}

func TestForcedCollisionIterateKeysValues(t *testing.T) {
	t.Parallel()

	h := data.NewHashMap[collidingKey, string]()
	k1 := collidingKey{id: 1, bucket: 7}
	k2 := collidingKey{id: 2, bucket: 7}
	k3 := collidingKey{id: 3, bucket: 7}
	h.Set(k1, "one")
	h.Set(k2, "two")
	h.Set(k3, "three")

	// Iterate must visit every colliding entry exactly once.
	visited := map[int]string{}
	h.Iterate(func(k collidingKey, v string) bool {
		if _, dup := visited[k.id]; dup {
			t.Errorf("Iterate revisited key id=%d", k.id)
		}
		visited[k.id] = v
		return true
	})
	for _, want := range []struct {
		id int
		v  string
	}{{1, "one"}, {2, "two"}, {3, "three"}} {
		if visited[want.id] != want.v {
			t.Errorf("Iterate missed key id=%d (got %q, want %q)", want.id, visited[want.id], want.v)
		}
	}

	// Early return from Iterate must stop the walk.
	count := 0
	h.Iterate(func(_ collidingKey, _ string) bool {
		count++
		return false
	})
	if count != 1 {
		t.Errorf("Iterate visit count with early return = %d; want 1", count)
	}

	// Keys and Values must return all colliding entries.
	if got := len(h.Keys()); got != 3 {
		t.Errorf("len(Keys) = %d; want 3", got)
	}
	if got := len(h.Values()); got != 3 {
		t.Errorf("len(Values) = %d; want 3", got)
	}
}

func TestForcedCollisionCloneIsIndependent(t *testing.T) {
	t.Parallel()

	h := data.NewHashMap[collidingKey, string]()
	k1 := collidingKey{id: 1, bucket: 9}
	k2 := collidingKey{id: 2, bucket: 9}
	h.Set(k1, "one")
	h.Set(k2, "two")

	c := h.Clone()

	// Mutating the clone must not touch the original (and vice versa).
	c.Set(k1, "one-clone")
	if got, _ := h.Get(k1); got != "one" {
		t.Errorf("Clone shares bucket storage: original.Get(k1) = %q after clone.Set; want %q", got, "one")
	}
	c.Remove(k2)
	if _, ok := h.Get(k2); !ok {
		t.Errorf("Clone shares bucket storage: original.Get(k2) missing after clone.Remove")
	}
	if h.Size() != 2 {
		t.Errorf("original.Size after clone mutation = %d; want 2", h.Size())
	}
}
