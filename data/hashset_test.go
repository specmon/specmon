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
	"testing"

	"github.com/specmon/specmon/data"
)

func TestHashSet(t *testing.T) {
	t.Parallel()

	h := data.NewHashSet[[]int]()

	if !h.Empty() {
		t.Errorf("%v should be empty", h)
	}

	h.Add([]int{1, 2, 3}, []int{4, 5, 6})

	ok := h.Contains([]int{1, 2, 3})
	if !ok {
		t.Errorf("%v should contain %d", h, 1)
	}

	if h.Size() != 2 {
		t.Errorf("%v should have size of %d, got %d", h, 2, h.Size())
	}

	h.Remove([]int{1, 2, 3})

	if h.Size() != 1 {
		t.Errorf("%v should have size of %d, got %d", h, 1, h.Size())
	}

	h.Remove([]int{4, 5, 6})

	if !h.Empty() {
		t.Errorf("%v should be empty", h)
	}
}
