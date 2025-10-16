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
	"errors"
	"testing"

	"github.com/specmon/specmon/term"
)

// TestFormatLengthConflict is a regression test for a critical bug where format
// patterns with different total length constraints could incorrectly unify with
// the same byte data, leading to ambiguous matches.
//
// Bug scenario:
// - Pattern A expects cat(byte(x, 2), byte(y, 3)) - total 5 bytes
// - Pattern B expects cat(byte(x, 2), byte(y, 5)) - total 7 bytes
// - Incoming data has 7 bytes
//
// Before fix: ParseFormat didn't properly validate that all bytes were consumed,
// allowing Pattern A to match the first 5 bytes of a 7-byte input. This caused
// both patterns to appear valid during unification in the monitor's conflictSet,
// leading to "cannot delete non-existing fact" errors when rules tried to apply.
//
// After fix: ParseFormat returns ErrSliceTooLong if not all bytes are consumed,
// ensuring only exact-length matches succeed. Pattern A fails on 7-byte data;
// only Pattern B succeeds.
func TestFormatLengthConflict(t *testing.T) {
	t.Parallel()

	// Pattern 1: expects exactly 5 bytes total
	shortPattern := []*term.Function{
		term.Must(term.AsFunction(term.NewFunction("byte", []term.Term{
			term.NewVariable("x"),
			term.NewConstant[int](2),
		}))),
		term.Must(term.AsFunction(term.NewFunction("byte", []term.Term{
			term.NewVariable("y"),
			term.NewConstant[int](3),
		}))),
	}

	// Pattern 2: expects exactly 7 bytes total
	longPattern := []*term.Function{
		term.Must(term.AsFunction(term.NewFunction("byte", []term.Term{
			term.NewVariable("x"),
			term.NewConstant[int](2),
		}))),
		term.Must(term.AsFunction(term.NewFunction("byte", []term.Term{
			term.NewVariable("y"),
			term.NewConstant[int](5),
		}))),
	}

	// Test data: 7 bytes
	sevenBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

	// Short pattern should FAIL on 7-byte data (too many bytes)
	_, err := term.ParseFormat(shortPattern, sevenBytes)
	if !errors.Is(err, term.ErrSliceTooLong) {
		t.Errorf("shortPattern on 7 bytes: expected ErrSliceTooLong, got %v", err)
	}

	// Long pattern should SUCCEED on 7-byte data
	binding, err := term.ParseFormat(longPattern, sevenBytes)
	if err != nil {
		t.Errorf("longPattern on 7 bytes: expected success, got %v", err)
	}
	if binding == nil {
		t.Fatal("longPattern on 7 bytes: expected non-nil binding")
	}

	// Verify the binding contains correct values
	xVar := term.NewVariable("x")
	yVar := term.NewVariable("y")

	expectedX := term.NewConstant[[]byte]([]byte{0x01, 0x02})
	expectedY := term.NewConstant[[]byte]([]byte{0x03, 0x04, 0x05, 0x06, 0x07})

	if boundX, ok := binding.Get(xVar); !ok || !boundX.Equal(expectedX) {
		t.Errorf("x binding incorrect: got %v, expected %v", boundX, expectedX)
	}
	if boundY, ok := binding.Get(yVar); !ok || !boundY.Equal(expectedY) {
		t.Errorf("y binding incorrect: got %v, expected %v", boundY, expectedY)
	}
}

// TestFormatLengthConflict_ShortData tests the opposite case: data that's too
// short should fail to match longer format patterns.
func TestFormatLengthConflict_ShortData(t *testing.T) {
	t.Parallel()

	// Pattern expects 7 bytes total
	longPattern := []*term.Function{
		term.Must(term.AsFunction(term.NewFunction("byte", []term.Term{
			term.NewVariable("x"),
			term.NewConstant[int](2),
		}))),
		term.Must(term.AsFunction(term.NewFunction("byte", []term.Term{
			term.NewVariable("y"),
			term.NewConstant[int](5),
		}))),
	}

	// Test data: only 5 bytes (too short)
	fiveBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// Should fail with ErrSliceTooShort
	_, err := term.ParseFormat(longPattern, fiveBytes)
	if !errors.Is(err, term.ErrSliceTooShort) {
		t.Errorf("longPattern on 5 bytes: expected ErrSliceTooShort, got %v", err)
	}
}

// TestFormatExactMatch verifies that patterns match only when the length is exact.
func TestFormatExactMatch(t *testing.T) {
	t.Parallel()

	pattern := []*term.Function{
		term.Must(term.AsFunction(term.NewFunction("byte", []term.Term{
			term.NewVariable("x"),
			term.NewConstant[int](3),
		}))),
		term.Must(term.AsFunction(term.NewFunction("byte", []term.Term{
			term.NewVariable("y"),
			term.NewConstant[int](2),
		}))),
	}

	testCases := []struct {
		name      string
		data      []byte
		shouldErr bool
		errType   error
	}{
		{
			name:      "exact length (5 bytes)",
			data:      []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			shouldErr: false,
		},
		{
			name:      "too short (4 bytes)",
			data:      []byte{0x01, 0x02, 0x03, 0x04},
			shouldErr: true,
			errType:   term.ErrSliceTooShort,
		},
		{
			name:      "too long (6 bytes)",
			data:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			shouldErr: true,
			errType:   term.ErrSliceTooLong,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			binding, err := term.ParseFormat(pattern, tc.data)
			if tc.shouldErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tc.errType != nil && !errors.Is(err, tc.errType) {
					t.Errorf("expected error %v, got %v", tc.errType, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected success, got error: %v", err)
				}
				if binding == nil {
					t.Error("expected non-nil binding on success")
				}
			}
		})
	}
}
