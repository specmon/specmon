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

package main

/*
func TestJSONUnmarshal(t *testing.T) {
	t.Parallel()

	type unmarshalTest struct {
		json        string
		expectFact  Fact
		expectError bool
	}

	unmarshalTests := []unmarshalTest{
		// Variable argument
		{`{"name": "State1", "args": [{"value": "x"}]}`, Fact{Name: "State1", Args: []term.Term{term.Variable{"x"}}}, false},

		// Int constant argument
		{`{"name": "State1", "args": [{"value": 1337}]}`, Fact{Name: "State1", Args: []term.Term{term.IntConstant{1337}}}, false},

		// Byte string constant argument
		{`{"name": "State1", "args": [{"value": "0xdeadbabe"}]}`, Fact{Name: "State1", Args: []term.Term{term.ByteStringConstant{[]byte("\xde\xad\xba\xbe")}}}, false},

		// Invalid byte string constant argument
		{`{"name": "State1", "args": [{"value": "0xdeadbab"}]}`, Fact{}, true},

		// Multiple arguments
		{`{"name": "State1", "args": [{"value": "0xdeadbabe"}, {"value": 1337}, {"value": "a"}]}`, Fact{Name: "State1", Args: []term.Term{term.ByteStringConstant{[]byte("\xde\xad\xba\xbe")}, term.IntConstant{1337}, term.Variable{"a"}}}, false},
	}

	for _, test := range unmarshalTests {
		var got Fact
		err := json.Unmarshal([]byte(test.json), &got)
		if err != nil {
			t.Log(err)
		}

		// If we have an error, we don't have to test the return value,
		// since it is in some partially initialized state.
		if err != nil {
			if !test.expectError {
				t.Fatalf("not expecting error but got one")
			}
			return
		}

		if !reflect.DeepEqual(got, test.expectFact) {
			t.Errorf("wrong fact: expected %#v, got %#v", test.expectFact, got)
		}
		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}
	}
}

func TestMatchBytestring(t *testing.T) {
	t.Parallel()

	type matchTest struct {
		binding     Binding
		bytestring  string
		spec        string
		expectValue map[string][]byte
		expectError bool
	}

	matchTests := []matchTest{
		// Empty specifiction
		{make(Binding), "0x01020304", "", nil, true},

		// Out-of-bounds specification
		{make(Binding), "0x01020304", "a:6", nil, true},

		// Section without length
		{make(Binding), "0x01020304", "0x01020304", nil, true},

		// Simple match
		{make(Binding), "0x01020304", "0x01020304:4", make(map[string][]byte), false},

		// Simple non-match
		{make(Binding), "0x02020304", "0x01020304:4", nil, true},

		// Invalid spec: bytestring longer than given length
		{make(Binding), "0x01020304", "0x01020304:3", nil, true},

		// Multiple simple sections
		{make(Binding), "0x01020304", "0x0102:2|0x0304:2", make(map[string][]byte), false},

		// term.Variable binding
		{make(Binding), "0x01020304", "a:4", map[string][]byte{"a": {0x01, 0x02, 0x03, 0x04}}, false},

		// Section with -1 length specification
		{make(Binding), "0x01020304", "a:-1", map[string][]byte{"a": {0x01, 0x02, 0x03, 0x04}}, false},

		// Section with -1 length specification with multiple sections
		{make(Binding), "0x01020304", "0x0102:2|a:-1", map[string][]byte{"a": {0x03, 0x04}}, false},

		// Section with -1 length specification in non-last section
		{make(Binding), "0x01020304", "0x0102:-1|a:2", nil, true},

		// Unbouned length term.Variable
		{make(Binding), "0x01020304", "0x010203004:a", nil, true},

		// Multiple term.Variable bindings
		{make(Binding), "0x01020304", "a:2|b:2", map[string][]byte{"a": {0x01, 0x02}, "b": {0x03, 0x04}}, false},

		// Use of term.Variable in length specification
		{make(Binding), "0x01020304", "0x01:1|a:1|b:a", map[string][]byte{"a": {0x02}, "b": {0x03, 0x04}}, false},

		// Overflow of length term.Variable
		{make(Binding), "0xffffffffffffffffffff00", "a:10|b:a", nil, true},

		// Example from simple_mac
		{
			make(Binding), "0x0b000000000000000148656c6c6f20776f726c641a5a913b60bde6818f86b5a2f6a44d50c4c56f83", "size:8|0x01:1|payload:size|hmac:-1",
			map[string][]byte{
				"hmac":    {0x1a, 0x5a, 0x91, 0x3b, 0x60, 0xbd, 0xe6, 0x81, 0x8f, 0x86, 0xb5, 0xa2, 0xf6, 0xa4, 0x4d, 0x50, 0xc4, 0xc5, 0x6f, 0x83},
				"payload": {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64},
				"size":    {0xb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			},
			false,
		},

		// Match with binding
		{map[term.Variable]term.IntConstant{{"a"}: {4}}, "0x01020304", "0x01020304:a", map[string][]byte{}, false},

		// Match with integers
		{make(Binding), "0xff00ff", "255:1|0:1|255:1", make(map[string][]byte), false},

		// Match with larger integer
		{make(Binding), "0xffffffffffffffffff", "0:9", nil, true},
	}

	for _, test := range matchTests {
		byteArr, err := hex.DecodeString(test.bytestring[2:])
		if err != nil {
			t.Fatalf("pre-test: Invalid test input %s", test.bytestring)
		}

		got, err := matchBytestring(test.binding, byteArr, test.spec)
		if err != nil {
			t.Log(err)
		}

		if !reflect.DeepEqual(got, test.expectValue) {
			t.Errorf("wrong binding: expected %#v, got %#v", test.expectValue, got)
		}
		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}
		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one")
		}
	}
}
*/
