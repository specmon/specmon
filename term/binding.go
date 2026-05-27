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

package term

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/specmon/specmon/data"
)

type Binding struct {
	m *data.HashMap[Term, Term]
}

func NewBinding() *Binding {
	return &Binding{
		m: data.NewHashMap[Term, Term](),
	}
}

func BindingFromMap(m map[Term]Term) *Binding {
	n := data.NewHashMap[Term, Term]()

	for k, v := range m {
		n.Set(k, v)
	}

	return &Binding{n}
}

func (b *Binding) ComputeFixpoint() *Binding {
	c := b

	for {
		modified := false
		c.Iterate(func(k, v Term) bool {
			if n := v.Subst(b); !n.Equal(v) {
				c.Set(k, n)
				modified = true
			}

			return true
		})
		if !modified {
			break
		}
	}

	return c
}

// Equal reports whether b and bp bind the same keys to the same values.
// It is symmetric: equal sizes plus the receiver's keys all matching the
// argument's values implies the reverse direction holds too.
func (b *Binding) Equal(bp *Binding) bool {
	if bp == nil {
		return b == nil || b.Size() == 0
	}
	if b == nil {
		return bp.Size() == 0
	}
	if b.Size() != bp.Size() {
		return false
	}

	equal := true
	b.Iterate(func(k, v Term) bool {
		if vp, ok := bp.Get(k); ok {
			if !v.Equal(vp) {
				equal = false
				return false
			}
		} else {
			equal = false
			return false
		}
		return true
	})

	return equal
}

func (b *Binding) String() string {
	var s string

	b.IterateSorted(func(k, v Term) bool {
		s += fmt.Sprintf("%s -> %s, ", k, v)

		return true
	})
	s = strings.TrimSuffix(s, ", ")

	return fmt.Sprintf("[ %s ]", s)
}

func (b *Binding) Compatible(bp *Binding) bool {
	compatible := true

	b.Iterate(func(k, v Term) bool {
		if vp, ok := bp.Get(k); ok {
			if !v.Equal(vp) {
				compatible = false

				return false
			}
		}

		return true
	})

	return compatible
}

func (b *Binding) Self() *Binding {
	return b
}

func (b *Binding) Hash() uint64 {
	h := fnv.New64a()

	b.IterateSorted(func(k, v Term) bool {
		var buf [8]byte

		binary.LittleEndian.PutUint64(buf[:], k.Hash())
		h.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], v.Hash())
		h.Write(buf[:])

		return true
	})

	return h.Sum64()
}

// Wrapper functions for HashMap.

func (b *Binding) Get(k Term) (Term, bool) {
	return b.m.Get(k)
}

func (b *Binding) Set(k, v Term) {
	b.m.Set(k, v)
}

func (b *Binding) Remove(k Term) {
	b.m.Remove(k)
}

func (b *Binding) Empty() bool {
	return b.m.Empty()
}

func (b *Binding) Size() int {
	return b.m.Size()
}

func (b *Binding) Iterate(f func(Term, Term) bool) {
	b.m.Iterate(f)
}

func (b *Binding) IterateSorted(f func(Term, Term) bool) {
	b.m.IterateSorted(f)
}

func (b *Binding) Clone() *Binding {
	return &Binding{b.m.Clone()}
}

func (b *Binding) Extend(bp *Binding) *Binding {
	return &Binding{b.m.Extend(bp.m)}
}
