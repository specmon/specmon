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
	"slices"
	"testing"

	"github.com/specmon/specmon/data"
)

func TestContains(t *testing.T) {
	t.Parallel()

	i := data.NewIndexSet[int]()

	if !i.Empty() {
		t.Errorf("%v should be empty", i)
	}

	i.Add(1, 1, 2, 2, 3, 4)

	if !i.Contains(1) {
		t.Errorf("%v should contain %d", i, 1)
	}
	if !i.Contains(2) {
		t.Errorf("%v should contain %d", i, 2)
	}
	if !i.Contains(3) {
		t.Errorf("%v should contain %d", i, 3)
	}
	if !i.Contains(4) {
		t.Errorf("%v should contain %d", i, 4)
	}

	if i.Size() != 4 {
		t.Errorf("%v should have size of %d, got %d", i, 4, i.Size())
	}

	if !slices.Equal(i.AsSlice(), []int{1, 2, 3, 4}) {
		t.Errorf("%v should have elements %v, got %v", i, []int{1, 2, 3, 4}, i.AsSlice())
	}

	i.Remove(1)
	if i.Size() != 3 {
		t.Errorf("%v should have size of %d, got %d", i, 3, i.Size())
	}

	i.Remove(2)
	if i.Size() != 2 {
		t.Errorf("%v should have size of %d, got %d", i, 2, i.Size())
	}

	i.Remove(3)
	if i.Size() != 1 {
		t.Errorf("%v should have size of %d, got %d", i, 1, i.Size())
	}

	i.Remove(4)
	if i.Size() != 0 {
		t.Errorf("%v should have size of %d, got %d", i, 0, i.Size())
	}

	if i.Contains(1) {
		t.Errorf("%v should not contain %d", i, 1)
	}

	if i.Contains(2) {
		t.Errorf("%v should not contain %d", i, 2)
	}
	if i.Contains(3) {
		t.Errorf("%v should not contain %d", i, 3)
	}
	if i.Contains(4) {
		t.Errorf("%v should not contain %d", i, 4)
	}
}
