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

//
// DAG data structure
//

type DAGNode[V any, E any] struct {
	value V
	// Invarient:
	//   If d is a parent of p then //   d is a child of p.
	parents  *IndexSet[*DAGNode[V, E]]
	children *IndexSet[*DAGNode[V, E]]

	// If labels[c] = e then children.Contains(c)
	labels map[*DAGNode[V, E]]E
}

func NewDAGNode[V, E any](v V) *DAGNode[V, E] {
	return &DAGNode[V, E]{
		value:    v,
		parents:  NewIndexSet[*DAGNode[V, E]](),
		children: NewIndexSet[*DAGNode[V, E]](),
		labels:   map[*DAGNode[V, E]]E{},
	}
}

func NewDAGNodeWithoutValue[V, E any]() *DAGNode[V, E] {
	return &DAGNode[V, E]{
		value:    *new(V),
		parents:  NewIndexSet[*DAGNode[V, E]](),
		children: NewIndexSet[*DAGNode[V, E]](),
		labels:   map[*DAGNode[V, E]]E{},
	}
}

func (d DAGNode[V, E]) Value() V {
	return d.value
}

func (d *DAGNode[V, E]) SetValue(v V) *DAGNode[V, E] {
	d.value = v

	return d
}

func (d DAGNode[V, E]) Parents() *IndexSet[*DAGNode[V, E]] {
	return d.parents
}

func (d DAGNode[V, E]) Children() *IndexSet[*DAGNode[V, E]] {
	return d.children
}

func (d DAGNode[V, E]) Label(c *DAGNode[V, E]) E {
	return d.labels[c]
}

// Add p as a parent of d.
func (d *DAGNode[V, E]) AddParents(P ...*DAGNode[V, E]) *DAGNode[V, E] {
	for _, p := range P {
		d.Parents().Add(p)
		p.Children().Add(d)
	}

	return d
}

// Add c as a child of d.
func (d *DAGNode[V, E]) AddChildren(C ...*DAGNode[V, E]) *DAGNode[V, E] {
	for _, c := range C {
		d.Children().Add(c)
		c.Parents().Add(d)
	}

	return d
}

func (d *DAGNode[V, E]) AddChildrenWithLabel(w E, C ...*DAGNode[V, E]) *DAGNode[V, E] {
	for _, c := range C {
		d.Children().Add(c)
		c.Parents().Add(d)
		d.labels[c] = w
	}

	return d
}

// Remove d as a child of p.
func (d *DAGNode[V, E]) RemoveParent(p *DAGNode[V, E]) *DAGNode[V, E] {
	d.Parents().Remove(p)
	p.Children().Remove(d)

	return d
}

// Remove d as a parent of c.
func (d *DAGNode[V, E]) RemoveChild(c *DAGNode[V, E]) *DAGNode[V, E] {
	d.Children().Remove(c)
	c.Parents().Remove(d)

	return d
}

// Remove d from all parents.
func (d *DAGNode[V, E]) Remove() *DAGNode[V, E] {
	for _, p := range d.Parents().AsSlice() {
		p.Children().Remove(d)
	}

	return d
}

func (d *DAGNode[V, E]) FindFunc(p func(*DAGNode[V, E]) bool) *DAGNode[V, E] {
	var f *DAGNode[V, E]

	d.Traverse(TraverseAll, TraverseBFS, true, func(n *DAGNode[V, E], _ E, _ int) bool {
		if p(n) {
			f = n

			return false
		}

		return true
	})

	return f
}

func (d *DAGNode[V, E]) Treeify(f func(v V, i int) V) *DAGNode[V, E] {
	d.Traverse(TraverseDown, TraverseDFS, true, func(n *DAGNode[V, E], _ E, _ int) bool {
		if n.Parents().Size() > 1 {
			for i, p := range n.Parents().AsSlice() {
				m := NewDAGNode[V, E](f(n.value, i))

				p.RemoveChild(n)
				p.AddChildren(m)

				for _, c := range n.Children().AsSlice() {
					m.AddChildren(NewDAGNode[V, E](c.Value()))
				}
			}
		}

		return true
	})

	return d
}

func (d *DAGNode[V, E]) Leaves() []*DAGNode[V, E] {
	L := make([]*DAGNode[V, E], 0)

	d.Traverse(TraverseDown, TraverseDFS, true, func(n *DAGNode[V, E], _ E, _ int) bool {
		if n.Children().Empty() {
			L = append(L, n)
		}

		return true
	})

	return L
}

func (d *DAGNode[V, E]) Roots() []*DAGNode[V, E] {
	R := make([]*DAGNode[V, E], 0)

	d.Traverse(TraverseUp, TraverseDFS, true, func(n *DAGNode[V, E], _ E, _ int) bool {
		if n.Parents().Empty() {
			R = append(R, n)
		}

		return true
	})

	return R
}

type (
	TraversalType      int
	TraversalDirection int
)

const (
	TraverseUp TraversalDirection = iota
	TraverseDown
	TraverseAll

	TraverseBFS TraversalType = iota
	TraverseDFS
)

func (d *DAGNode[V, E]) Traverse(dir TraversalDirection, typ TraversalType, visitOnce bool, f func(*DAGNode[V, E], E, int) bool) *DAGNode[V, E] {
	Q := []*DAGNode[V, E]{d}
	S := NewSet(d)
	L := []int{0}
	var n *DAGNode[V, E]
	var l int
	var next *IndexSet[*DAGNode[V, E]]

	P := map[*DAGNode[V, E]]*DAGNode[V, E]{
		d: nil,
	}

	for {
		if len(Q) == 0 {
			return d
		}

		switch typ {
		case TraverseBFS:
			n, Q = Q[len(Q)-1], Q[:len(Q)-1]
			l, L = L[len(L)-1], L[:len(L)-1]
		case TraverseDFS:
			n, Q = Q[0], Q[1:]
			l, L = L[0], L[1:]
		}

		var label E
		if P[n] != nil {
			switch dir {
			case TraverseDown:
				label = P[n].Label(n)
			case TraverseUp:
				label = n.Label(P[n])
			}
		}

		if !f(n, label, l) {
			return d
		}

		switch dir {
		case TraverseUp:
			next = n.Parents()
		case TraverseDown:
			next = n.Children()
		case TraverseAll:
			next = NewIndexSet[*DAGNode[V, E]]()
			next.Add(n.Parents().AsSlice()...)
			next.Add(n.Children().AsSlice()...)
		}

		for _, m := range next.AsSlice() {
			if !visitOnce || !S.Contains(m) {
				Q = append(Q, m)
				L = append(L, l+1)
				S.Add(m)
				P[m] = n
			}
		}
	}
}

func (d *DAGNode[V, E]) StringTree() string {
	var s string

	d.Traverse(TraverseDown, TraverseBFS, false, func(d *DAGNode[V, E], w E, l int) bool {
		s += fmt.Sprintf("%s%v | %v (P: %d, C: %d) [%p]\n", strings.Repeat(" ", 2*l), w, d.Value(), d.Parents().Size(), d.Children().Size(), &d.value)

		return true
	})

	return s
}

func (d *DAGNode[V, E]) String() string {
	return fmt.Sprintf("%v (P: %d, C: %d) [%p]", d.Value(), d.Parents().Size(), d.Children().Size(), &d.value)
}

// LabeledBy returns all the parent labels of d.
func (d *DAGNode[V, E]) LabeldBy() []E {
	labels := make([]E, d.Parents().Size())

	for i, p := range d.Parents().AsSlice() {
		labels[i] = p.Label(d)
	}

	return labels
}

// Depth returns the length of the longest path from d to a leaf.
func (d *DAGNode[V, E]) Depth() int {
	var m int

	d.Traverse(TraverseDown, TraverseBFS, false, func(_ *DAGNode[V, E], _ E, l int) bool {
		if l > m {
			m = l
		}

		return true
	})

	return m
}
