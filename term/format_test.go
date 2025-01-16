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
	"encoding/hex"
	"strings"
	"testing"

	"github.com/specmon/specmon/term"
)

func TestBytesToConstant(t *testing.T) {
	t.Parallel()

	type bytesTest struct {
		bytes       string
		formatType  term.FormatType
		expectValue term.Term
		expectError bool
	}

	tests := []bytesTest{
		{
			"0x01020304",
			term.FormatByteType,
			term.NewConstant[[]byte]([]byte{0x01, 0x02, 0x03, 0x04}),
			false,
		},
		{
			"0x",
			term.FormatByteType,
			term.NewConstant[[]byte]([]byte{}),
			false,
		},
		{
			"0x01",
			term.FormatIntType,
			term.NewConstant[int](1),
			false,
		},
		{
			"0x66",
			term.FormatIntType,
			term.NewConstant[int](102),
			false,
		},
		{
			"Hello, world!",
			term.FormatStringType,
			term.NewConstant[string]("Hello, world!"),
			false,
		},
		{
			"0xffffffffffffffffffffffffffffffffffffffffff",
			term.FormatIntType,
			nil,
			true,
		},
	}

	for _, test := range tests {
		bytes := []byte(test.bytes)

		if strings.HasPrefix(test.bytes, "0x") {
			var err error
			bytes, err = hex.DecodeString(test.bytes[2:])
			if err != nil {
				t.Fatalf("pre-test: Invalid test input %s", test.bytes)
			}
		}

		got, err := term.FormatTypeToConstant(test.formatType, bytes)

		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one: %s", err.Error())
		}

		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}

		if err == nil && !got.Equal(test.expectValue) {
			t.Errorf("wrong binding:\n expected %s\n got      %s", test.expectValue, got)
		}
	}
}

/*
func TestFormatToBytes(t *testing.T) {
	// t.Parallel()

	type bytesTest struct {
		format      []term.Function
		binding     *term.Binding
		expectValue string
		expectError bool
	}

	bytesTests := []bytesTest{
		// Example from simple_mac
		{
			// int(size, 8), byte(1), byte(payload, size), byte(hmac)
			[]term.Function{
				*term.NewFunction("int", []term.Term{
					term.NewVariable("size"),
					term.NewConstant[int](8),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewConstant[[]byte]([]byte{0x01}),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("payload"),
					term.NewVariable("size"),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("hmac"),
				}),
			},
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("size"):    term.NewConstant[int](11),
				term.NewVariable("payload"): term.NewConstant[[]byte]([]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64}),
				term.NewVariable("hmac"):    term.NewConstant[[]byte]([]byte{0x1a, 0x5a, 0x91, 0x3b, 0x60, 0xbd, 0xe6, 0x81, 0x8f, 0x86, 0xb5, 0xa2, 0xf6, 0xa4, 0x4d, 0x50, 0xc4, 0xc5, 0x6f, 0x83}),
			}),
			"0x0b000000000000000148656c6c6f20776f726c641a5a913b60bde6818f86b5a2f6a44d50c4c56f83",
			false,
		},
		{
			// byte(0x60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36), string('WireGuard v1 zx2c4 Jason@zx2c4.com')
			[]term.Function{
				*term.NewFunction("byte", []term.Term{
					term.NewConstant[[]byte]([]byte{
						0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
					}),
				}),
				*term.NewFunction("string", []term.Term{
					term.NewConstant[string]("WireGuard v1 zx2c4 Jason@zx2c4.com"),
				}),
			},
			term.NewBinding(),
			"0x60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36576972654775617264207631207a78326334204a61736f6e407a783263342e636f6d",
			false,
		},
	}

	for _, test := range bytesTests {
		expected, err := hex.DecodeString(test.expectValue[2:])
		if err != nil {
			t.Fatalf("pre-test: Invalid test input %s", test.expectValue)
		}

		got, err := term.FormatToBytes(test.format, test.binding)
		if err != nil {
			t.Log(err)
		}

		if !bytes.Equal(got, expected) {
			t.Errorf("wrong bytes:\n expected %s\n got      %s", test.expectValue, "0x"+hex.EncodeToString(got))
		}

		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}

		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one: %s", err.Error())
		}
	}
}

func TestParseFormat(t *testing.T) {
	// t.Parallel()

	type parseTest struct {
		binding     term.Binding
		bytes       string
		format      []term.Function
		expectValue *term.Binding
		expectError bool
	}

	parseTests := []parseTest{
		//		// Empty specifiction
		//		{make(term.Binding), "0x01020304", "", nil, true},

		//		// Out-of-bounds specification
		//		{make(term.Binding), "0x01020304", "a:6", nil, true},
		//
		//		// Section without length
		//		{make(term.Binding), "0x01020304", "0x01020304", nil, true},
		//
		// Simple match
		// {make(term.Binding), "0x01020304", []term.Function{*term.NewFunction("byte", []term.Term{term.NewConstant([]byte{0x01, 0x02, 0x03, 0x04})})}, make(map[term.Variable]term.Constant), false},
		//
		//		// Simple non-match
		//		{make(term.Binding), "0x02020304", "0x01020304:4", nil, true},
		//
		//		// Invalid spec: bytestring longer than given length
		//		{make(term.Binding), "0x01020304", "0x01020304:3", nil, true},
		//
		//		// Multiple simple sections
		//		{make(term.Binding), "0x01020304", "0x0102:2|0x0304:2", term.NewBinding(), false},
		//
		// term.Variable binding
		// {make(term.Binding), "0x01020304", []term.Function{*term.NewFunction("byte", []term.Term{term.NewVariable("a"), term.NewConstant(4)})}, map[term.Variable]term.Constant{*term.NewVariable("a"): *term.NewConstant([]byte{0x01, 0x02, 0x03, 0x04})}, false},

		// Int conversion
		// {make(term.Binding), "0x0b000000", []term.Function{*term.NewFunction("int", []term.Term{term.NewVariable("a"), term.NewConstant(4)})}, map[term.Variable]term.Constant{*term.NewVariable("a"): *term.NewConstant(11)}, false},
		//
		//		// Section with -1 length specification
		//		{make(term.Binding), "0x01020304", "a:-1", term.NewBindingFromMap(map[string][]byte{"a": {0x01, 0x02, 0x03, 0x04}}), false},
		//
		//		// Section with -1 length specification with multiple sections
		//		{make(term.Binding), "0x01020304", "0x0102:2|a:-1", term.NewBindingFromMap(map[string][]byte{"a": {0x03, 0x04}}), false},
		//
		//		// Section with -1 length specification in non-last section
		//		{make(term.Binding), "0x01020304", "0x0102:-1|a:2", nil, true},
		//
		//		// Unbouned length term.Variable
		//		{make(term.Binding), "0x01020304", "0x010203004:a", nil, true},
		//
		//		// Multiple term.Variable bindings
		//		{make(term.Binding), "0x01020304", "a:2|b:2", term.NewBindingFromMap(map[string][]byte{"a": {0x01, 0x02}, "b": {0x03, 0x04}}), false},
		//
		//		// Use of term.Variable in length specification
		//		{make(term.Binding), "0x01020304", "0x01:1|a:1|b:a", term.NewBindingFromMap(map[string][]byte{"a": {0x02}, "b": {0x03, 0x04}}), false},
		//
		//		// Overflow of length term.Variable
		//		{make(term.Binding), "0xffffffffffffffffffff00", "a:10|b:a", nil, true},
		//
		// Example from simple_mac
		{
			*term.NewBinding(), "0x0b000000000000000148656c6c6f20776f726c641a5a913b60bde6818f86b5a2f6a44d50c4c56f83", // "size:8|0x01:1|payload:size|hmac:-1",
			// int(size, 8), byte(1), byte(payload, size), byte(hmac)
			[]term.Function{
				*term.NewFunction("int", []term.Term{
					term.NewVariable("size"),
					term.NewConstant[int](8),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewConstant[[]byte]([]byte{0x01}),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("payload"),
					term.NewVariable("size"),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("hmac"),
				}),
			},
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("size"):    term.NewConstant[int](11),
				term.NewVariable("payload"): term.NewConstant[[]byte]([]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64}),
				term.NewVariable("hmac"):    term.NewConstant[[]byte]([]byte{0x1a, 0x5a, 0x91, 0x3b, 0x60, 0xbd, 0xe6, 0x81, 0x8f, 0x86, 0xb5, 0xa2, 0xf6, 0xa4, 0x4d, 0x50, 0xc4, 0xc5, 0x6f, 0x83}),
			}),
			false,
		},
		//
		//		// Match with binding
		//		{term.Binding{*term.NewVariable("a"): term.NewConstant(4)}, "0x01020304", "0x01020304:a", term.NewBinding(), false},
		//
		//		// Match with integers
		//		{make(term.Binding), "0xff00ff", "255:1|0:1|255:1", term.NewBinding(), false},
		//
		//		// Match with larger integer
		//		{make(term.Binding), "0xffffffffffffffffff", "0:9", nil, true},
	}

	for _, test := range parseTests {
		bytes, err := hex.DecodeString(test.bytes[2:])
		if err != nil {
			t.Fatalf("pre-test: Invalid test input %s", test.bytes)
		}

		got, err := term.ParseFormat(test.format, bytes)
		if err != nil {
			t.Log(err)
		}

		if !got.Equal(test.expectValue) {
			t.Errorf("wrong binding:\n expected %s\n got      %s", test.expectValue, got)
		}

		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}

		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one: %s", err.Error())
		}
	}
}

func TestFormatToBytes(t *testing.T) {
	// t.Parallel()

	type bytesTest struct {
		format      []term.Function
		binding     *term.Binding
		expectValue string
		expectError bool
	}

	bytesTests := []bytesTest{
		// Example from simple_mac
		{
			// int(size, 8), byte(1), byte(payload, size), byte(hmac)
			[]term.Function{
				*term.NewFunction("int", []term.Term{
					term.NewVariable("size"),
					term.NewConstant[int](8),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewConstant[[]byte]([]byte{0x01}),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("payload"),
					term.NewVariable("size"),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("hmac"),
				}),
			},
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("size"):    term.NewConstant[int](11),
				term.NewVariable("payload"): term.NewConstant[[]byte]([]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64}),
				term.NewVariable("hmac"):    term.NewConstant[[]byte]([]byte{0x1a, 0x5a, 0x91, 0x3b, 0x60, 0xbd, 0xe6, 0x81, 0x8f, 0x86, 0xb5, 0xa2, 0xf6, 0xa4, 0x4d, 0x50, 0xc4, 0xc5, 0x6f, 0x83}),
			}),
			"0x0b000000000000000148656c6c6f20776f726c641a5a913b60bde6818f86b5a2f6a44d50c4c56f83",
			false,
		},
		{
			// byte(0x60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36), string('WireGuard v1 zx2c4 Jason@zx2c4.com')
			[]term.Function{
				*term.NewFunction("byte", []term.Term{
					term.NewConstant[[]byte]([]byte{
						0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
					}),
				}),
				*term.NewFunction("string", []term.Term{
					term.NewConstant[string]("WireGuard v1 zx2c4 Jason@zx2c4.com"),
				}),
			},
			term.NewBinding(),
			"0x60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36576972654775617264207631207a78326334204a61736f6e407a783263342e636f6d",
			false,
		},
	}

	for _, test := range bytesTests {
		expected, err := hex.DecodeString(test.expectValue[2:])
		if err != nil {
			t.Fatalf("pre-test: Invalid test input %s", test.expectValue)
		}

		got, err := term.FormatToBytes(test.format, test.binding)
		if err != nil {
			t.Log(err)
		}

		if !bytes.Equal(got, expected) {
			t.Errorf("wrong bytes:\n expected %s\n got      %s", test.expectValue, "0x"+hex.EncodeToString(got))
		}

		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}

		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one: %s", err.Error())
		}
	}
}

func TestParseFormat(t *testing.T) {
	// t.Parallel()

	type parseTest struct {
		binding     term.Binding
		bytes       string
		format      []term.Function
		expectValue *term.Binding
		expectError bool
	}

	parseTests := []parseTest{
		//		// Empty specifiction
		//		{make(term.Binding), "0x01020304", "", nil, true},

		//		// Out-of-bounds specification
		//		{make(term.Binding), "0x01020304", "a:6", nil, true},
		//
		//		// Section without length
		//		{make(term.Binding), "0x01020304", "0x01020304", nil, true},
		//
		// Simple match
		// {make(term.Binding), "0x01020304", []term.Function{*term.NewFunction("byte", []term.Term{term.NewConstant([]byte{0x01, 0x02, 0x03, 0x04})})}, make(map[term.Variable]term.Constant), false},
		//
		//		// Simple non-match
		//		{make(term.Binding), "0x02020304", "0x01020304:4", nil, true},
		//
		//		// Invalid spec: bytestring longer than given length
		//		{make(term.Binding), "0x01020304", "0x01020304:3", nil, true},
		//
		//		// Multiple simple sections
		//		{make(term.Binding), "0x01020304", "0x0102:2|0x0304:2", term.NewBinding(), false},
		//
		// term.Variable binding
		// {make(term.Binding), "0x01020304", []term.Function{*term.NewFunction("byte", []term.Term{term.NewVariable("a"), term.NewConstant(4)})}, map[term.Variable]term.Constant{*term.NewVariable("a"): *term.NewConstant([]byte{0x01, 0x02, 0x03, 0x04})}, false},

		// Int conversion
		// {make(term.Binding), "0x0b000000", []term.Function{*term.NewFunction("int", []term.Term{term.NewVariable("a"), term.NewConstant(4)})}, map[term.Variable]term.Constant{*term.NewVariable("a"): *term.NewConstant(11)}, false},
		//
		//		// Section with -1 length specification
		//		{make(term.Binding), "0x01020304", "a:-1", term.NewBindingFromMap(map[string][]byte{"a": {0x01, 0x02, 0x03, 0x04}}), false},
		//
		//		// Section with -1 length specification with multiple sections
		//		{make(term.Binding), "0x01020304", "0x0102:2|a:-1", term.NewBindingFromMap(map[string][]byte{"a": {0x03, 0x04}}), false},
		//
		//		// Section with -1 length specification in non-last section
		//		{make(term.Binding), "0x01020304", "0x0102:-1|a:2", nil, true},
		//
		//		// Unbouned length term.Variable
		//		{make(term.Binding), "0x01020304", "0x010203004:a", nil, true},
		//
		//		// Multiple term.Variable bindings
		//		{make(term.Binding), "0x01020304", "a:2|b:2", term.NewBindingFromMap(map[string][]byte{"a": {0x01, 0x02}, "b": {0x03, 0x04}}), false},
		//
		//		// Use of term.Variable in length specification
		//		{make(term.Binding), "0x01020304", "0x01:1|a:1|b:a", term.NewBindingFromMap(map[string][]byte{"a": {0x02}, "b": {0x03, 0x04}}), false},
		//
		//		// Overflow of length term.Variable
		//		{make(term.Binding), "0xffffffffffffffffffff00", "a:10|b:a", nil, true},
		//
		// Example from simple_mac
		{
			*term.NewBinding(), "0x0b000000000000000148656c6c6f20776f726c641a5a913b60bde6818f86b5a2f6a44d50c4c56f83", // "size:8|0x01:1|payload:size|hmac:-1",
			// int(size, 8), byte(1), byte(payload, size), byte(hmac)
			[]term.Function{
				*term.NewFunction("int", []term.Term{
					term.NewVariable("size"),
					term.NewConstant[int](8),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewConstant[[]byte]([]byte{0x01}),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("payload"),
					term.NewVariable("size"),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("hmac"),
				}),
			},
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("size"):    term.NewConstant[int](11),
				term.NewVariable("payload"): term.NewConstant[[]byte]([]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64}),
				term.NewVariable("hmac"):    term.NewConstant[[]byte]([]byte{0x1a, 0x5a, 0x91, 0x3b, 0x60, 0xbd, 0xe6, 0x81, 0x8f, 0x86, 0xb5, 0xa2, 0xf6, 0xa4, 0x4d, 0x50, 0xc4, 0xc5, 0x6f, 0x83}),
			}),
			false,
		},
		//
		//		// Match with binding
		//		{term.Binding{*term.NewVariable("a"): term.NewConstant(4)}, "0x01020304", "0x01020304:a", term.NewBinding(), false},
		//
		//		// Match with integers
		//		{make(term.Binding), "0xff00ff", "255:1|0:1|255:1", term.NewBinding(), false},
		//
		//		// Match with larger integer
		//		{make(term.Binding), "0xffffffffffffffffff", "0:9", nil, true},
	}

	for _, test := range parseTests {
		bytes, err := hex.DecodeString(test.bytes[2:])
		if err != nil {
			t.Fatalf("pre-test: Invalid test input %s", test.bytes)
		}

		got, err := term.ParseFormat(test.format, bytes)
		if err != nil {
			t.Log(err)
		}

		if !got.Equal(test.expectValue) {
			t.Errorf("wrong binding:\n expected %s\n got      %s", test.expectValue, got)
		}

		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}

		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one: %s", err.Error())
		}
	}
}

func TestFormatToBytes(t *testing.T) {
	// t.Parallel()

	type bytesTest struct {
		format      []term.Function
		binding     *term.Binding
		expectValue string
		expectError bool
	}

	bytesTests := []bytesTest{
		// Example from simple_mac
		{
			// int(size, 8), byte(1), byte(payload, size), byte(hmac)
			[]term.Function{
				*term.NewFunction("int", []term.Term{
					term.NewVariable("size"),
					term.NewConstant[int](8),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewConstant[[]byte]([]byte{0x01}),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("payload"),
					term.NewVariable("size"),
				}),
				*term.NewFunction("byte", []term.Term{
					term.NewVariable("hmac"),
				}),
			},
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("size"):    term.NewConstant[int](11),
				term.NewVariable("payload"): term.NewConstant[[]byte]([]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64}),
				term.NewVariable("hmac"):    term.NewConstant[[]byte]([]byte{0x1a, 0x5a, 0x91, 0x3b, 0x60, 0xbd, 0xe6, 0x81, 0x8f, 0x86, 0xb5, 0xa2, 0xf6, 0xa4, 0x4d, 0x50, 0xc4, 0xc5, 0x6f, 0x83}),
			}),
			"0x0b000000000000000148656c6c6f20776f726c641a5a913b60bde6818f86b5a2f6a44d50c4c56f83",
			false,
		},
		{
			// byte(0x60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36), string('WireGuard v1 zx2c4 Jason@zx2c4.com')
			[]term.Function{
				*term.NewFunction("byte", []term.Term{
					term.NewConstant[[]byte]([]byte{
						0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
					}),
				}),
				*term.NewFunction("string", []term.Term{
					term.NewConstant[string]("WireGuard v1 zx2c4 Jason@zx2c4.com"),
				}),
			},
			term.NewBinding(),
			"0x60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36576972654775617264207631207a78326334204a61736f6e407a783263342e636f6d",
			false,
		},
	}

	for _, test := range bytesTests {
		expected, err := hex.DecodeString(test.expectValue[2:])
		if err != nil {
			t.Fatalf("pre-test: Invalid test input %s", test.expectValue)
		}

		got, err := term.FormatToBytes(test.format, test.binding)
		if err != nil {
			t.Log(err)
		}

		if !bytes.Equal(got, expected) {
			t.Errorf("wrong bytes:\n expected %s\n got      %s", test.expectValue, "0x"+hex.EncodeToString(got))
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
