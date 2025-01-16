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
	"slices"

	"golang.org/x/exp/maps"
)

//
// Set data strucure
//

type Set[T comparable] map[T]bool

func NewSet[T comparable](e ...T) Set[T] {
	return make(Set[T]).Add(e...)
}

func (s Set[T]) Contains(e T) bool {
	_, ok := s[e]

	return ok
}

func (s Set[T]) Add(e ...T) Set[T] {
	for _, v := range e {
		s[v] = true
	}

	return s
}

func (s Set[T]) Remove(e T) Set[T] {
	delete(s, e)

	return s
}

func (s Set[T]) AsSlice() []T {
	return maps.Keys(s)
}

func (s Set[T]) AsSliceSorted(cmp func(a, b T) int) []T {
	e := maps.Keys(s)
	slices.SortFunc(e, cmp)

	return e
}

func (s Set[T]) Empty() bool {
	return len(s) == 0
}

func (s Set[T]) Size() int {
	return len(s)
}

func (s Set[T]) String() string {
	return fmt.Sprintf("%v", s.AsSlice())
}
