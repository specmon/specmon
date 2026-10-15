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

package data

import (
	"fmt"
	"hash"
	"hash/fnv"
	"maps"
	"slices"
	"strings"
)

type Hasher interface {
	Hash() uint64
}

type HashMap[K, V any] struct {
	m map[uint64]Entry[K, V]
	h hash.Hash64
}

type Entry[K, V any] struct {
	Key   K
	Value V
}

func NewHashMap[K, V any]() *HashMap[K, V] {
	return &HashMap[K, V]{
		m: make(map[uint64]Entry[K, V]),
		h: fnv.New64a(),
	}
}

func (h *HashMap[K, V]) hash(k K) uint64 {
	var b []byte

	switch t := any(k).(type) {
	case Hasher:
		return t.Hash()
	case fmt.Stringer:
		b = []byte(t.String())
	default:
		b = fmt.Appendf(nil, "%v", k)
	}

	h.h.Reset()
	h.h.Write(b)

	return h.h.Sum64()
}

func (h *HashMap[K, V]) Get(k K) (V, bool) {
	entry, ok := h.m[h.hash(k)]

	return entry.Value, ok
}

func (h *HashMap[K, V]) Set(k K, v V) {
	h.m[h.hash(k)] = Entry[K, V]{k, v}
}

func (h *HashMap[K, V]) Remove(k K) {
	delete(h.m, h.hash(k))
}

func (h *HashMap[K, V]) Empty() bool {
	return len(h.m) == 0
}

// Keys returns the keys in ascending order of their hashes, so that the
// order does not change from run to run.
func (h *HashMap[K, V]) Keys() []K {
	keys := make([]K, 0, h.Size())
	for _, hash := range h.sortedHashes() {
		keys = append(keys, h.m[hash].Key)
	}
	return keys
}

// Values returns the values in ascending order of the hashes of their keys.
func (h *HashMap[K, V]) Values() []V {
	values := make([]V, 0, h.Size())
	for _, hash := range h.sortedHashes() {
		values = append(values, h.m[hash].Value)
	}
	return values
}

func (h *HashMap[K, V]) sortedHashes() []uint64 {
	hashes := make([]uint64, 0, len(h.m))
	for hash := range h.m {
		hashes = append(hashes, hash)
	}
	slices.Sort(hashes)
	return hashes
}

func (h *HashMap[K, V]) Size() int {
	return len(h.m)
}

func (h *HashMap[K, V]) String() string {
	s := "HashMap["

	for _, hash := range h.sortedHashes() {
		entry := h.m[hash]
		s += fmt.Sprintf("%v", entry.Key)
		s += ":"
		s += fmt.Sprintf("%v", entry.Value)
		s += " "
	}
	s = strings.TrimSuffix(s, " ")

	return s + "]"
}

func (h *HashMap[K, V]) Iterate(f func(K, V) bool) {
	for _, hash := range h.sortedHashes() {
		entry, ok := h.m[hash]
		if !ok {
			continue
		}
		if !f(entry.Key, entry.Value) {
			break
		}
	}
}

// IterateSorted is Iterate, which visits the entries in hash order.
func (h *HashMap[K, V]) IterateSorted(f func(K, V) bool) {
	h.Iterate(f)
}

func (h *HashMap[K, V]) Clone() *HashMap[K, V] {
	c := &HashMap[K, V]{
		m: make(map[uint64]Entry[K, V], len(h.m)),
	}

	maps.Copy(c.m, h.m)

	return c
}

func (h *HashMap[K, V]) Extend(hp *HashMap[K, V]) *HashMap[K, V] {
	u := h.Clone()

	maps.Copy(u.m, hp.m)

	return u
}
