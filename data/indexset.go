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

import "fmt"

type IndexSet[T comparable] struct {
	mapping  map[T]int
	freelist []int
	elements []T
}

func NewIndexSet[T comparable](e ...T) *IndexSet[T] {
	i := &IndexSet[T]{
		mapping:  make(map[T]int),
		freelist: make([]int, 0),
		elements: make([]T, 0),
	}

	return i.Add(e...)
}

func (i IndexSet[T]) Contains(e T) bool {
	_, ok := i.mapping[e]

	return ok
}

func (i *IndexSet[T]) Add(e ...T) *IndexSet[T] {
	for _, v := range e {
		if i.Contains(v) {
			continue
		}

		var index int
		if len(i.freelist) == 0 {
			index = len(i.elements)
			i.mapping[v] = index
			i.elements = append(i.elements, v)
		} else {
			index = i.freelist[0]
			i.freelist = i.freelist[1:]
			i.mapping[v] = index
			i.elements[index] = v
		}

		if i.elements[index] != v {
			panic("i.elements[index] != v")
		}
	}

	return i
}

func (i *IndexSet[T]) Remove(e T) *IndexSet[T] {
	index := i.mapping[e]
	i.freelist = append(i.freelist, index)
	delete(i.mapping, e)

	return i
}

func (i *IndexSet[T]) AsSlice() []T {
	present := make([]T, 0)

	for j, e := range i.elements {
		if k, ok := i.mapping[e]; !ok || j != k {
			continue
		}
		present = append(present, e)
	}

	return present
}

func (i *IndexSet[T]) Empty() bool {
	return len(i.mapping) == 0
}

func (i *IndexSet[T]) Size() int {
	return len(i.mapping)
}

func (i *IndexSet[T]) String() string {
	return fmt.Sprintf("%v %v %v", i.mapping, i.freelist, i.elements)
}
