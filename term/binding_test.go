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

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/term"
)

type Equaler[T any] interface {
	Equal(other T) bool
	Self() T
}

func appendIfUnique[T any, E Equaler[T]](s []E, e E) []E {
	for _, v := range s {
		if v.Equal(e.Self()) {
			fmt.Printf("%v == %v\n", v, e.Self())

			return s
		}
	}

	return append(s, e)
}

func TestBinding(t *testing.T) {
	t.Parallel()

	b1 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("x"): term.NewConstant(1),
		term.NewVariable("y"): term.NewConstant(2),
	})

	b2 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("y"): term.NewConstant(2),
		term.NewVariable("x"): term.NewConstant(1),
	})

	b3 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("y"): term.NewConstant(3),
		term.NewVariable("x"): term.NewConstant(1),
	})

	var B []*term.Binding
	B = appendIfUnique(B, b1)
	B = appendIfUnique(B, b2)
	B = appendIfUnique(B, b3)

	if len(B) != 2 {
		t.Errorf("Expected 2 bindings, got %d", len(B))
	}
}

func TestBindingHashSet(t *testing.T) {
	t.Parallel()

	b := []*term.Binding{
		term.BindingFromMap(map[term.Term]term.Term{
			term.NewVariable("x"): term.NewConstant(1),
			term.NewVariable("y"): term.NewConstant(2),
		}),

		term.BindingFromMap(map[term.Term]term.Term{
			term.NewVariable("y"): term.NewConstant(2),
			term.NewVariable("x"): term.NewConstant(1),
		}),

		term.BindingFromMap(map[term.Term]term.Term{
			term.NewVariable("y"): term.NewConstant(3),
			term.NewVariable("x"): term.NewConstant(1),
		}),
	}

	h := data.NewHashSet(b...)

	fmt.Println(h)

	if h.Size() != 2 {
		t.Errorf("Expected 2 bindings, got %d", h.Size())
	}
}

// Binding.Equal previously walked only the receiver, so a strict subset
// {x->1} would compare equal to its superset {x->1, y->2} in one
// direction. Equal must be a true equivalence relation because callers
// like data.HashMap use it to dedupe colliding keys.
func TestBindingEqualIsSymmetric(t *testing.T) {
	t.Parallel()

	small := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("x"): term.NewConstant(1),
	})
	large := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("x"): term.NewConstant(1),
		term.NewVariable("y"): term.NewConstant(2),
	})

	if small.Equal(large) {
		t.Error("small.Equal(large) should be false (sizes differ)")
	}
	if large.Equal(small) {
		t.Error("large.Equal(small) should be false (sizes differ)")
	}

	// And the symmetric positive case still holds.
	other := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("y"): term.NewConstant(2),
		term.NewVariable("x"): term.NewConstant(1),
	})
	if !large.Equal(other) {
		t.Error("large.Equal(other) should be true (same keys, same values)")
	}
	if !other.Equal(large) {
		t.Error("other.Equal(large) should be true (symmetry)")
	}
}
