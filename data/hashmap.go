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

package data

import (
	"fmt"
	"hash"
	"hash/fnv"
	"reflect"
	"sort"
	"strings"
)

type Hasher interface {
	Hash() uint64
}

type HashMap[K, V any] struct {
	m map[uint64][]Entry[K, V]
	h hash.Hash64
}

type Entry[K, V any] struct {
	Key   K
	Value V
}

// equaler[K] is the contract used to disambiguate two K values that
// land in the same hash bucket. It must be a symmetric equivalence
// relation: a.Equal(b) == b.Equal(a). Asymmetric implementations
// (e.g. a subset test) will silently dedupe distinct keys when their
// hashes happen to collide.
type equaler[K any] interface {
	Equal(K) bool
}

// keysEqual compares two K values for in-bucket equality, in this order:
//  1. K's own Equal[K] method, if implemented.
//  2. Go's == operator, if K is comparable (e.g. pointers, structs of
//     comparables).
//  3. reflect.DeepEqual as a last resort, for non-comparable composite
//     types like []T or map[K]V. This path is rare in production —
//     the codebase uses pointer or Equaler keys — but is required by
//     HashSet[[]int] in tests.
func keysEqual[K any](a, b K) bool {
	if eq, ok := any(a).(equaler[K]); ok {
		return eq.Equal(b)
	}
	if t := reflect.TypeOf(a); t != nil && t.Comparable() {
		return any(a) == any(b)
	}
	return reflect.DeepEqual(a, b)
}

func NewHashMap[K, V any]() *HashMap[K, V] {
	return &HashMap[K, V]{
		m: make(map[uint64][]Entry[K, V]),
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
		b = []byte(fmt.Sprintf("%v", k))
	}

	h.h.Reset()
	h.h.Write(b)

	return h.h.Sum64()
}

func (h *HashMap[K, V]) Get(k K) (V, bool) {
	var zero V
	bucket, ok := h.m[h.hash(k)]
	if !ok {
		return zero, false
	}
	for _, entry := range bucket {
		if keysEqual(entry.Key, k) {
			return entry.Value, true
		}
	}
	return zero, false
}

func (h *HashMap[K, V]) Set(k K, v V) {
	hash := h.hash(k)
	bucket := h.m[hash]
	for i, entry := range bucket {
		if keysEqual(entry.Key, k) {
			bucket[i].Value = v
			h.m[hash] = bucket
			return
		}
	}
	h.m[hash] = append(bucket, Entry[K, V]{k, v})
}

func (h *HashMap[K, V]) Remove(k K) {
	hash := h.hash(k)
	bucket, ok := h.m[hash]
	if !ok {
		return
	}
	for i, entry := range bucket {
		if keysEqual(entry.Key, k) {
			bucket = append(bucket[:i], bucket[i+1:]...)
			if len(bucket) == 0 {
				delete(h.m, hash)
			} else {
				h.m[hash] = bucket
			}
			return
		}
	}
}

func (h *HashMap[K, V]) Empty() bool {
	return h.Size() == 0
}

func (h *HashMap[K, V]) Keys() []K {
	keys := make([]K, 0, h.Size())

	for _, bucket := range h.m {
		for _, entry := range bucket {
			keys = append(keys, entry.Key)
		}
	}

	return keys
}

func (h *HashMap[K, V]) Values() []V {
	values := make([]V, 0, h.Size())

	for _, bucket := range h.m {
		for _, entry := range bucket {
			values = append(values, entry.Value)
		}
	}

	return values
}

func (h *HashMap[K, V]) Size() int {
	n := 0
	for _, bucket := range h.m {
		n += len(bucket)
	}
	return n
}

func (h *HashMap[K, V]) String() string {
	s := "HashMap["

	for _, bucket := range h.m {
		for _, entry := range bucket {
			s += fmt.Sprintf("%v", entry.Key)
			s += ":"
			s += fmt.Sprintf("%v", entry.Value)
			s += " "
		}
	}
	s = strings.TrimSuffix(s, " ")

	return s + "]"
}

func (h *HashMap[K, V]) Iterate(f func(K, V) bool) {
	for _, bucket := range h.m {
		for _, entry := range bucket {
			if !f(entry.Key, entry.Value) {
				return
			}
		}
	}
}

func (h *HashMap[K, V]) IterateSorted(f func(K, V) bool) {
	keys := make([]uint64, 0, len(h.m))

	for k := range h.m {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	for _, k := range keys {
		for _, entry := range h.m[k] {
			if !f(entry.Key, entry.Value) {
				return
			}
		}
	}
}

func (h *HashMap[K, V]) Clone() *HashMap[K, V] {
	c := &HashMap[K, V]{
		m: make(map[uint64][]Entry[K, V], len(h.m)),
		h: fnv.New64a(),
	}

	for k, bucket := range h.m {
		copied := make([]Entry[K, V], len(bucket))
		copy(copied, bucket)
		c.m[k] = copied
	}

	return c
}

func (h *HashMap[K, V]) Extend(hp *HashMap[K, V]) *HashMap[K, V] {
	u := h.Clone()

	hp.Iterate(func(k K, v V) bool {
		u.Set(k, v)
		return true
	})

	return u
}
