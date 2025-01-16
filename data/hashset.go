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
	"strings"
)

type HashSet[T any] struct {
	m HashMap[T, struct{}]
}

func NewHashSet[T any](e ...T) *HashSet[T] {
	h := &HashSet[T]{
		m: *NewHashMap[T, struct{}](),
	}

	h.Add(e...)

	return h
}

func (h HashSet[T]) Contains(e T) bool {
	_, ok := h.m.Get(e)

	return ok
}

func (h HashSet[T]) Add(e ...T) {
	for _, v := range e {
		h.m.Set(v, struct{}{})
	}
}

func (h HashSet[T]) Remove(e T) {
	h.m.Remove(e)
}

func (h HashSet[T]) Empty() bool {
	return h.m.Empty()
}

func (h HashSet[T]) Size() int {
	return h.m.Size()
}

func (h HashSet[T]) Values() []T {
	return h.m.Keys()
}

func (h HashSet[T]) String() string {
	s := "HashSet["

	for _, entry := range h.m.m {
		s += fmt.Sprintf("%v", entry.Key)
		s += " "
	}
	s = strings.TrimSuffix(s, " ")

	return s + "]"
}

func (h HashSet[T]) Iterate(f func(T) bool) {
	for _, entry := range h.m.m {
		if !f(entry.Key) {
			break
		}
	}
}

func (h HashSet[T]) Union(h1 *HashSet[T]) *HashSet[T] {
	h2 := NewHashSet[T]()

	h.Iterate(func(e T) bool {
		h2.Add(e)

		return true
	})

	h1.Iterate(func(e T) bool {
		h2.Add(e)

		return true
	})

	return h2
}
