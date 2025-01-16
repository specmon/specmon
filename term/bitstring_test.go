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

/*

func TestMatchBytestring(t *testing.T) {
	t.Parallel()

	type matchTest struct {
		binding     term.Binding
		bytestring  string
		spec        string
		expectValue term.Binding
		expectError bool
	}

	matchTests := []matchTest{
		// Empty specifiction
		{make(term.Binding), "0x01020304", "", nil, true},

		// Out-of-bounds specification
		{make(term.Binding), "0x01020304", "a:6", nil, true},

		// Section without length
		{make(term.Binding), "0x01020304", "0x01020304", nil, true},

		// Simple match
		{make(term.Binding), "0x01020304", "0x01020304:4", term.NewBinding(), false},

		// Simple non-match
		{make(term.Binding), "0x02020304", "0x01020304:4", nil, true},

		// Invalid spec: bytestring longer than given length
		{make(term.Binding), "0x01020304", "0x01020304:3", nil, true},

		// Multiple simple sections
		{make(term.Binding), "0x01020304", "0x0102:2|0x0304:2", term.NewBinding(), false},

		// term.Variable binding
		{make(term.Binding), "0x01020304", "a:4", term.NewBindingFromMap(map[string][]byte{"a": {0x01, 0x02, 0x03, 0x04}}), false},

		// Section with -1 length specification
		{make(term.Binding), "0x01020304", "a:-1", term.NewBindingFromMap(map[string][]byte{"a": {0x01, 0x02, 0x03, 0x04}}), false},

		// Section with -1 length specification with multiple sections
		{make(term.Binding), "0x01020304", "0x0102:2|a:-1", term.NewBindingFromMap(map[string][]byte{"a": {0x03, 0x04}}), false},

		// Section with -1 length specification in non-last section
		{make(term.Binding), "0x01020304", "0x0102:-1|a:2", nil, true},

		// Unbouned length term.Variable
		{make(term.Binding), "0x01020304", "0x010203004:a", nil, true},

		// Multiple term.Variable bindings
		{make(term.Binding), "0x01020304", "a:2|b:2", term.NewBindingFromMap(map[string][]byte{"a": {0x01, 0x02}, "b": {0x03, 0x04}}), false},

		// Use of term.Variable in length specification
		{make(term.Binding), "0x01020304", "0x01:1|a:1|b:a", term.NewBindingFromMap(map[string][]byte{"a": {0x02}, "b": {0x03, 0x04}}), false},

		// Overflow of length term.Variable
		{make(term.Binding), "0xffffffffffffffffffff00", "a:10|b:a", nil, true},

		// Example from simple_mac
		{
			make(term.Binding), "0x0b000000000000000148656c6c6f20776f726c641a5a913b60bde6818f86b5a2f6a44d50c4c56f83", "size:8|0x01:1|payload:size|hmac:-1",
			term.NewBindingFromMap(map[string][]byte{
				"hmac":    {0x1a, 0x5a, 0x91, 0x3b, 0x60, 0xbd, 0xe6, 0x81, 0x8f, 0x86, 0xb5, 0xa2, 0xf6, 0xa4, 0x4d, 0x50, 0xc4, 0xc5, 0x6f, 0x83},
				"payload": {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64},
				"size":    {0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			}),
			false,
		},

		// Match with binding
		{term.Binding{*term.NewVariable("a"): term.NewConstant(4)}, "0x01020304", "0x01020304:a", term.NewBinding(), false},

		// Match with integers
		{make(term.Binding), "0xff00ff", "255:1|0:1|255:1", term.NewBinding(), false},

		// Match with larger integer
		{make(term.Binding), "0xffffffffffffffffff", "0:9", nil, true},
	}

	for _, test := range matchTests {
		byteArr, err := hex.DecodeString(test.bytestring[2:])
		if err != nil {
			t.Fatalf("pre-test: Invalid test input %s", test.bytestring)
		}

		got, err := term.MatchBitstring(test.binding, byteArr, test.spec)
		if err != nil {
			t.Log(err)
		}

		if !got.Equal(&test.expectValue) {
			t.Errorf("wrong binding: expected %#v, got %#v", test.expectValue, got)
		}
		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}
		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one: %s", err.Error())
		}
	}
}

*/
