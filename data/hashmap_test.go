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

package data_test

import (
	"fmt"
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

func TestCollision(t *testing.T) {
	t.Parallel()

	h := data.NewHashMap[string, int]()

	h.Set("creamwove", 1)
	h.Set("quists", 2)

	if h.Size() != 2 {
		t.Errorf("%v should have size of %d, got %d", h, 2, h.Size())
	}
}

// hashedKey is a key with a given hash.
type hashedKey uint64

func (k hashedKey) Hash() uint64 { return uint64(k) }

// TestHashMapOrdersByHash checks that the keys and values come in
// ascending order of the key hashes, whatever the order of insertion.
func TestHashMapOrdersByHash(t *testing.T) {
	t.Parallel()

	h := data.NewHashMap[hashedKey, int]()
	set := data.NewHashSet[hashedKey]()
	for _, k := range []hashedKey{42, 7, 1 << 63, 0, 99, 3} {
		h.Set(k, int(k%100))
		set.Add(k)
	}
	var iterated []hashedKey
	h.Iterate(func(k hashedKey, _ int) bool {
		iterated = append(iterated, k)
		return true
	})
	want := "[0 3 7 42 99 9223372036854775808] [0 3 7 42 99 8] [0 3 7 42 99 9223372036854775808] [0 3 7 42 99 9223372036854775808] " +
		"HashMap[0:0 3:3 7:7 42:42 99:99 9223372036854775808:8] HashSet[0 3 7 42 99 9223372036854775808]"
	if got := fmt.Sprint(h.Keys(), h.Values(), set.Values(), iterated, h, set); got != want {
		t.Fatalf("keys, values, set values, iteration and strings = %s, want %s", got, want)
	}
}

// TestHashMapIterateSkipsRemovedEntries checks that Iterate does not visit
// entries that the callback has removed.
func TestHashMapIterateSkipsRemovedEntries(t *testing.T) {
	t.Parallel()

	h := data.NewHashMap[hashedKey, string]()
	for _, k := range []hashedKey{1, 2, 3} {
		h.Set(k, "present")
	}
	var visited []hashedKey
	h.Iterate(func(k hashedKey, _ string) bool {
		visited = append(visited, k)
		h.Remove(2)
		h.Remove(3)
		return true
	})
	if !slices.Equal(visited, []hashedKey{1}) {
		t.Fatalf("visited %v, want [1]", visited)
	}
}
