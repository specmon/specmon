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

package utils_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/specmon/specmon/utils"
)

func TestIndent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		n        int
		expected string
	}{
		{
			input:    "Hello\nWorld",
			n:        2,
			expected: "  Hello\n  World\n",
		},
		{
			input:    "Lorem\nIpsum\nDolor",
			n:        4,
			expected: "    Lorem\n    Ipsum\n    Dolor\n",
		},
		{
			input:    "123\n456\n789",
			n:        0,
			expected: "123\n456\n789\n",
		},
	}

	for _, test := range tests {
		output := utils.Indent(test.input, test.n)
		if output != test.expected {
			t.Errorf("Incorrect indentation for input:\n%s\nExpected:\n%s\nGot:\n%s\n", test.input, test.expected, output)
		}
	}
}

func TestNumberLines(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		offset   int
		expected string
	}{
		{
			input:    "Hello\nWorld",
			offset:   0,
			expected: " 1 │ Hello\n 2 │ World\n",
		},
		{
			input:    "Lorem\nIpsum\nDolor",
			offset:   5,
			expected: " 6 │ Lorem\n 7 │ Ipsum\n 8 │ Dolor\n",
		},
		{
			input:    "123\n456\n789",
			offset:   -3,
			expected: " -2 │ 123\n -1 │ 456\n  0 │ 789\n",
		},
		{
			input:    "123\n456\n789",
			offset:   10000,
			expected: " 10001 │ 123\n 10002 │ 456\n 10003 │ 789\n",
		},
	}

	for _, test := range tests {
		output := utils.NumberLines(test.input, test.offset)
		if output != test.expected {
			t.Errorf("Incorrect number lines for input:\n%s\nExpected:\n%s\nGot:\n%s\n", test.input, test.expected, output)
		}
	}
}

func TestUnique(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    []fmt.Stringer
		expected []fmt.Stringer
	}{
		{
			input:    []fmt.Stringer{mockStringer("a"), mockStringer("b"), mockStringer("a")},
			expected: []fmt.Stringer{mockStringer("a"), mockStringer("b")},
		},
		{
			input:    []fmt.Stringer{mockStringer("x"), mockStringer("y"), mockStringer("z")},
			expected: []fmt.Stringer{mockStringer("x"), mockStringer("y"), mockStringer("z")},
		},
		{
			input:    []fmt.Stringer{mockStringer("a"), mockStringer("a"), mockStringer("a")},
			expected: []fmt.Stringer{mockStringer("a")},
		},
	}

	for _, test := range tests {
		output := utils.Unique(test.input)
		if !equal(output, test.expected) {
			t.Errorf("Incorrect unique values for input:\n%v\nExpected:\n%v\nGot:\n%v\n", test.input, test.expected, output)
		}
	}
}

type mockStringer string

func (m mockStringer) String() string {
	return string(m)
}

func equal(a, b []fmt.Stringer) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].String() != b[i].String() {
			return false
		}
	}

	return true
}

func TestBytesToInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    []byte
		order    binary.ByteOrder
		expected int
		err      error
	}{
		{
			input:    []byte{0x01, 0x02, 0x03, 0x04},
			order:    binary.BigEndian,
			expected: 16909060,
			err:      nil,
		},
		{
			input:    []byte{0x04, 0x03, 0x02, 0x01},
			order:    binary.LittleEndian,
			expected: 16909060,
			err:      nil,
		},
		{
			input:    []byte{0x01, 0x02, 0x03},
			order:    binary.BigEndian,
			expected: 66051,
			err:      nil,
		},
		{
			input:    []byte{0x03, 0x02, 0x01},
			order:    binary.LittleEndian,
			expected: 66051,
			err:      nil,
		},
		{
			input:    []byte{0x01},
			order:    binary.BigEndian,
			expected: 1,
			err:      nil,
		},
		{
			input:    []byte{0x01},
			order:    binary.LittleEndian,
			expected: 1,
			err:      nil,
		},
		{
			input:    []byte{},
			order:    binary.BigEndian,
			expected: 0,
			err:      nil,
		},
		{
			input:    []byte{},
			order:    binary.LittleEndian,
			expected: 0,
			err:      nil,
		},
	}

	for _, test := range tests {
		output, err := utils.BytesToInt(test.input, test.order)
		if output != test.expected {
			t.Errorf("Incorrect conversion for input:\n%v\nExpected:\n%d\nGot:\n%d\n", test.input, test.expected, output)
		}
		if !errors.Is(err, test.err) {
			t.Errorf("Incorrect error for input:\n%v\nExpected:\n%v\nGot:\n%v\n", test.input, test.err, err)
		}
	}
}

func TestIntToBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    int
		order    binary.ByteOrder
		expected []byte
		err      error
	}{
		{
			input:    16909060,
			order:    binary.BigEndian,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04},
			err:      nil,
		},
		{
			input:    16909060,
			order:    binary.LittleEndian,
			expected: []byte{0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00},
			err:      nil,
		},
		{
			input:    66051,
			order:    binary.BigEndian,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03},
			err:      nil,
		},
		{
			input:    66051,
			order:    binary.LittleEndian,
			expected: []byte{0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:      nil,
		},
		{
			input:    1,
			order:    binary.BigEndian,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			err:      nil,
		},
		{
			input:    1,
			order:    binary.LittleEndian,
			expected: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:      nil,
		},
	}

	for _, test := range tests {
		output := utils.IntToBytes(test.input, test.order)
		if !bytes.Equal(output, test.expected) {
			t.Errorf("Incorrect conversion for input:\n%d\nExpected:\n%v\nGot:\n%v\n", test.input, test.expected, output)
		}
	}
}

func TestPadWithByteOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    []byte
		order    binary.ByteOrder
		length   int
		expected []byte
	}{
		{
			input:    []byte{0x01, 0x02, 0x03},
			order:    binary.LittleEndian,
			length:   5,
			expected: []byte{0x01, 0x02, 0x03, 0x00, 0x00},
		},
		{
			input:    []byte{0x01, 0x02, 0x03},
			order:    binary.BigEndian,
			length:   5,
			expected: []byte{0x00, 0x00, 0x01, 0x02, 0x03},
		},
		{
			input:    []byte{0x01, 0x02, 0x03},
			order:    binary.LittleEndian,
			length:   3,
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			input:    []byte{0x01, 0x02, 0x03},
			order:    binary.BigEndian,
			length:   3,
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			input:    []byte{0x01, 0x02, 0x03},
			order:    binary.LittleEndian,
			length:   0,
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			input:    []byte{0x01, 0x02, 0x03},
			order:    binary.BigEndian,
			length:   0,
			expected: []byte{0x01, 0x02, 0x03},
		},
	}

	for _, test := range tests {
		output := utils.PadWithByteOrder(test.input, test.order, test.length)
		if !bytes.Equal(output, test.expected) {
			t.Errorf("Incorrect padding for input:\n%v\nOrder: %v\nLength: %d\nExpected:\n%v\nGot:\n%v\n", test.input, test.order, test.length, test.expected, output)
		}
	}
}

func TestPluralze(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		n        int
		expected string
	}{
		{
			input:    "apple",
			n:        1,
			expected: "apple",
		},
		{
			input:    "apple",
			n:        0,
			expected: "apples",
		},
		{
			input:    "apple",
			n:        2,
			expected: "apples",
		},
		{
			input:    "apple",
			n:        100,
			expected: "apples",
		},
		{
			input:    "apple",
			n:        -1,
			expected: "apples",
		},
	}

	for _, test := range tests {
		output := utils.Pluralize(test.input, test.n)
		if output != test.expected {
			t.Errorf("Incorrect pluralization for input:\n%s\nExpected:\n%s\nGot:\n%s\n", test.input, test.expected, output)
		}
	}
}
