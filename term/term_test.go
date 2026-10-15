// Copyright (C) 2025-2026 CISPA Helmholtz Center for Information Security
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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package term_test

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/specmon/specmon/term"
)

func TestEqualWithKind(t *testing.T) {
	integer := term.NewConstant(int64(97))
	integerBytes := term.NewConstant([]byte{97, 0, 0, 0, 0, 0, 0, 0})
	text := term.NewConstant("a")
	bytes := term.NewConstant([]byte("a"))
	nested := func(value term.Term) term.Term { return term.NewFunction("nested", []term.Term{value}) }
	for _, test := range []struct {
		name        string
		left, right term.Term
		equal       bool
	}{
		{"same integer", integer, term.NewConstant(int64(97)), true},
		{"integer and bytes", integer, integerBytes, false},
		{"string and bytes", text, bytes, false},
		{"same string", text, term.NewConstant("a"), true},
		{"same bytes", bytes, term.NewConstant([]byte("a")), true},
		{"nested integer and bytes", nested(integer), nested(integerBytes), false},
		{"nested string and bytes", nested(text), nested(bytes), false},
		{"nested same bytes", nested(bytes), nested(term.NewConstant([]byte("a"))), true},
		{"nil and empty bytes", term.NewConstant[[]byte](nil), term.NewConstant([]byte{}), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := term.EqualWithKind(test.left, test.right); got != test.equal {
				t.Fatalf("EqualWithKind(%s,%s)=%v; want %v", test.left, test.right, got, test.equal)
			}
		})
	}
}

func TestCompatible(t *testing.T) {
	t.Parallel()

	b1 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("x"): term.NewConstant[int64](1),
		term.NewVariable("y"): term.NewConstant[int64](2),
	})
	b2 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("y"): term.NewConstant[int64](2),
		term.NewVariable("z"): term.NewConstant[int64](3),
	})
	b3 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("y"): term.NewConstant[int64](3),
		term.NewVariable("z"): term.NewConstant[int64](3),
	})

	if !b1.Compatible(b2) || !b2.Compatible(b1) {
		t.Errorf("%+v and %+v should be compatible", b1, b2)
	}

	if b1.Compatible(b3) || b3.Compatible(b1) {
		t.Errorf("%+v and %+v should NOT be compatible", b1, b3)
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()

	b1 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("x"): term.NewConstant[int64](1),
		term.NewVariable("y"): term.NewConstant[int64](2),
	})
	b2 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("a"): term.NewConstant[int64](3),
		term.NewVariable("b"): term.NewConstant[int64](4),
	})

	expect := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("x"): term.NewConstant[int64](1),
		term.NewVariable("y"): term.NewConstant[int64](2),
		term.NewVariable("a"): term.NewConstant[int64](3),
		term.NewVariable("b"): term.NewConstant[int64](4),
	})

	if got := b1.Extend(b2); !expect.Equal(got) {
		t.Errorf("unify of %v and %v should be %v, got %v", b1, b2, expect, got)
	}
}

func TestUnify(t *testing.T) {
	t.Parallel()

	type unifyTest struct {
		t1            term.Term
		t2            term.Term
		expectbinding *term.Binding
		expectError   bool
	}

	unifyTests := []unifyTest{
		{
			// unify(x, 1) | [ x -> 1 ]
			term.NewVariable("x"),
			term.NewConstant[int64](1),
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("x"): term.NewConstant[int64](1),
			}),
			false,
		},
		{
			// unify(f(1, x), f(y, 2)) | [ x -> 2, y -> 1 ]
			term.NewFunction("f", []term.Term{term.NewConstant[int64](1), term.NewVariable("x")}),
			term.NewFunction("f", []term.Term{term.NewVariable("y"), term.NewConstant[int64](2)}),
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("x"): term.NewConstant[int64](2),
				term.NewVariable("y"): term.NewConstant[int64](1),
			}),
			false,
		},
		{
			// unify(f(x, y), f(y, x)) | [ x -> y ]
			term.NewFunction("f", []term.Term{term.NewVariable("x"), term.NewVariable("y")}),
			term.NewFunction("f", []term.Term{term.NewVariable("y"), term.NewVariable("x")}),
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("x"): term.NewVariable("y"),
			}),
			false,
		},
		{
			// unify(cat(int(11)), 0x0b00000000000000) | [ ]
			term.NewFunction("cat", []term.Term{term.NewFunction("int", []term.Term{term.NewConstant[int64](11)})}),
			term.NewConstant[[]byte]([]byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			term.NewBinding(),
			false,
		},
		{
			// unify(cat(int(11)), 0x0b00000000000000) | [ ]
			term.NewFunction("cat", []term.Term{term.NewFunction("int", []term.Term{term.NewConstant[int64](11)})}),
			term.NewConstant[[]byte]([]byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			term.NewBinding(),
			false,
		},
		{
			// unify(cat(int(length, 1), int(a, length), byte(b, length)), 0x0203000400) | [ length -> 2, a -> 3, b -> 0x0400 ]
			term.NewFunction("cat", []term.Term{
				term.NewFunction("int", []term.Term{
					term.NewVariable("length"),
					term.NewConstant[int64](1),
				}),
				term.NewFunction("int", []term.Term{
					term.NewVariable("a"),
					term.NewVariable("length"),
				}),
				term.NewFunction("byte", []term.Term{
					term.NewVariable("b"),
					term.NewVariable("length"),
				}),
			}),
			term.NewConstant[[]byte]([]byte{0x02, 0x03, 0x00, 0x04, 0x00}),
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("length"): term.NewConstant[int64](2),
				term.NewVariable("a"):      term.NewConstant[int64](3),
				term.NewVariable("b"):      term.NewConstant[[]byte]([]byte{0x04, 0x00}),
			}),
			false,
		},
		{
			// unify(Fn("Out", <0xdeadbabe, 40>, <>), Fn("init", <k, m>, <>)) | [ ]
			term.NewFunction("Fn", []term.Term{
				term.NewConstant[string]("Out"),
				term.NewFunction("pair", []term.Term{
					term.NewConstant[[]byte]([]byte{0xde, 0xad, 0xba, 0xbe}),
					term.NewConstant[int64](40),
				}),
				term.NewFunction("pair", []term.Term{}),
			}),
			term.NewFunction("Fn", []term.Term{
				term.NewConstant[string]("init"),
				term.NewFunction("pair", []term.Term{
					term.NewVariable("k"),
					term.NewVariable("m"),
				}),
				term.NewFunction("pair", []term.Term{}),
			}),
			term.NewBinding(),
			true,
		},
	}

	for _, test := range unifyTests {
		got, err := term.Unify(test.t1, test.t2)
		if err != nil {
			t.Log(err)
		}

		if !got.Equal(test.expectbinding) {
			t.Errorf("wrong binding:\n expected %s\n got      %s", test.expectbinding, got)
		}

		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}

		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one: %s", err.Error())
		}
	}
}

func TestUnifyReturnsEvaluationErrors(t *testing.T) {
	t.Parallel()

	invalid := term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant[int64](1)})
	_, err := invalid.Unify(term.NewConstant[int64](1))
	if !errors.Is(err, term.ErrEvaluation) {
		t.Fatalf("Unify error = %v, want ErrEvaluation", err)
	}
	if !errors.Is(err, term.ErrBinaryArity) {
		t.Fatalf("Unify error = %v, want wrapped ErrBinaryArity", err)
	}
}

func TestReplaceFormatsReturnsEvaluationErrors(t *testing.T) {
	t.Parallel()

	invalid := term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant[int64](1)})
	_, err := term.ReplaceFormats(invalid)
	if !errors.Is(err, term.ErrEvaluation) {
		t.Fatalf("ReplaceFormats error = %v, want ErrEvaluation", err)
	}
	if !errors.Is(err, term.ErrBinaryArity) {
		t.Fatalf("ReplaceFormats error = %v, want wrapped ErrBinaryArity", err)
	}

	partial := term.NewFunction(term.AddFunctionName, []term.Term{
		term.NewVariable("x"),
		term.NewConstant[int64](1),
	})
	got, err := term.ReplaceFormats(partial)
	if err != nil {
		t.Fatalf("ReplaceFormats returned an error for an unbound term: %v", err)
	}
	if !got.Equal(partial) {
		t.Fatalf("ReplaceFormats returned %s, want unchanged %s", got, partial)
	}
}

func TestEvaluate(t *testing.T) {
	t.Parallel()

	type evaluateTest struct {
		t           term.Term
		expectTerm  term.Term
		expectError bool
	}

	evaluateTests := []evaluateTest{
		{
			// evaluate('1') | '1'
			term.NewConstant[int64](1),
			term.NewConstant[int64](1),
			false,
		},
		{
			// evaluate('x') | 'x'
			term.NewVariable("x"),
			term.NewVariable("x"),
			false,
		},
		{
			// evaluate(add('1', '1')) | '2'
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewConstant[int64](1),
				term.NewConstant[int64](1),
			}),
			term.NewConstant[int64](2),
			false,
		},
		{
			// evaluate(add('x', '1')) | add('x', '2')
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewVariable("x"),
				term.NewConstant[int64](1),
			}),
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewVariable("x"),
				term.NewConstant[int64](1),
			}),
			false,
		},
		{
			// evaluate(add(add('1', '2'), '1')) | '4'
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewFunction(term.AddFunctionName, []term.Term{
					term.NewConstant[int64](1),
					term.NewConstant[int64](2),
				}),
				term.NewConstant[int64](1),
			}),
			term.NewConstant[int64](4),
			false,
		},
		{
			// evaluate(add(cat(byte('0x01'), byte('0x00'))), '1') | 1 + 1 = 2
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewFunction(term.CatFunctionName, []term.Term{
					term.NewFunction(string(term.FormatByteType), []term.Term{
						term.NewConstant[[]byte]([]byte{0x01}),
					}),
					term.NewFunction(string(term.FormatByteType), []term.Term{
						term.NewConstant[[]byte]([]byte{0x00}),
					}),
				}),
				term.NewConstant[int64](1),
			}),
			term.NewConstant[int64](2),
			false,
		},
		{
			// evaluate(and('0xf3', 248)) | 0xf0
			term.NewFunction(term.AndFunctionName, []term.Term{
				term.NewConstant[[]byte]([]byte{0xf3}),
				term.NewConstant[int64](248),
			}),
			term.NewConstant[[]byte]([]byte{0xf0}),
			false,
		},
		{
			// evaluate(and(243, 248)) | 243
			term.NewFunction(term.AndFunctionName, []term.Term{
				term.NewConstant[int64](243),
				term.NewConstant[int64](248),
			}),
			term.NewConstant[int64](240),
			false,
		},
		{
			// evaluate(or(and('0x30', '127'), '64')) | 0x70
			term.NewFunction(term.OrFunctionName, []term.Term{
				term.NewFunction(term.AndFunctionName, []term.Term{
					term.NewConstant[[]byte]([]byte{0x30}),
					term.NewConstant[int64](127),
				}),
				term.NewConstant[int64](64),
			}),
			term.NewConstant[[]byte]([]byte{0x70}),
			false,
		},
		{
			// ekI = cat( byte(and('0x3f', '248'), '1'), byte('0xbfe12c4f8e0d10f3f361ae081089edbef9a6953e8846269b1218efaf62a1', '30), byte(or(and('0x30', '127'), '64'), '1'))
			term.NewFunction(term.CatFunctionName, []term.Term{
				term.NewFunction(string(term.FormatByteType), []term.Term{
					term.NewFunction(term.AndFunctionName, []term.Term{
						term.NewConstant[[]byte]([]byte{0xf3}),
						term.NewConstant[int64](248),
					}),
				}),
				term.NewFunction(string(term.FormatByteType), []term.Term{
					term.NewConstant[[]byte]([]byte{
						0xbf, 0xe1, 0x2c, 0x4f, 0x8e, 0x0d, 0x10, 0xf3, 0xf3, 0x61, 0xae, 0x08, 0x10, 0x89, 0xed, 0xbe, 0xf9, 0xa6, 0x95, 0x3e, 0x88, 0x46, 0x26, 0x9b, 0x12, 0x18, 0xef, 0xaf, 0x62, 0xa1,
					}),
				}),
				term.NewFunction(string(term.FormatByteType), []term.Term{
					term.NewFunction(term.OrFunctionName, []term.Term{
						term.NewFunction(term.AndFunctionName, []term.Term{
							term.NewConstant[[]byte]([]byte{0x30}),
							term.NewConstant[int64](127),
						}),
						term.NewConstant[int64](64),
					}),
				}),
			}),
			term.NewConstant[[]byte]([]byte{
				0xf0, 0xbf, 0xe1, 0x2c, 0x4f, 0x8e, 0x0d, 0x10, 0xf3, 0xf3, 0x61, 0xae, 0x08, 0x10, 0x89, 0xed, 0xbe, 0xf9, 0xa6, 0x95, 0x3e, 0x88, 0x46, 0x26, 0x9b, 0x12, 0x18, 0xef, 0xaf, 0x62, 0xa1, 0x70,
			}),
			false,
		},

		/*
			{
				// evaluate(cat(byte(0x01), cat(byte(0x02), byte(0x03)))) | 0x010203
				term.NewFunction(term.CatFunctionName, []term.Term{
					term.NewFunction(string(term.FormatByteType), []term.Term{
						term.NewConstant[[]byte]([]byte{0x01}),
					}),
					term.NewFunction(term.CatFunctionName, []term.Term{
						term.NewFunction(string(term.FormatByteType), []term.Term{
							term.NewConstant[[]byte]([]byte{0x02}),
						}),
						term.NewFunction(string(term.FormatByteType), []term.Term{
							term.NewConstant[[]byte]([]byte{0x03}),
						}),
					}),
				}),
				term.NewConstant[[]byte]([]byte{0x01, 0x02, 0x03}),
				false,
			},
		*/
	}

	for _, test := range evaluateTests {
		got, err := term.Evaluate(test.t)
		if err != nil {
			t.Log(err)
		}

		if !got.Equal(test.expectTerm) {
			t.Errorf("wrong term:\n expected %s\n got      %s", test.expectTerm, got)
		}

		if err == nil && test.expectError {
			t.Errorf("expected error but got none")
		}

		if err != nil && !test.expectError {
			t.Errorf("not expecting error but got one: %s", err.Error())
		}
	}
}

func TestEvaluateCheckedAddition(t *testing.T) {
	t.Parallel()

	add := func(left, right term.Term) term.Term {
		return term.NewFunction(term.AddFunctionName, []term.Term{left, right})
	}
	for _, test := range []struct {
		name  string
		left  term.Term
		right term.Term
		want  int64
	}{
		{"zero", term.NewConstant[int64](0), term.NewConstant[int64](0), 0},
		{"ordinary", term.NewConstant[int64](40), term.NewConstant[int64](2), 42},
		{"mixed byte widths", term.NewConstant([]byte{0xff}), term.NewConstant([]byte{0x01, 0x00}), 256},
		{"maximum", term.NewConstant[int64](math.MaxInt64), term.NewConstant[int64](0), math.MaxInt64},
		{"nested left", add(term.NewConstant[int64](math.MaxInt64-2), term.NewConstant[int64](1)), term.NewConstant[int64](1), math.MaxInt64},
		{"nested right", term.NewConstant[int64](math.MaxInt64 - 2), add(term.NewConstant[int64](1), term.NewConstant[int64](1)), math.MaxInt64},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := term.Evaluate(add(test.left, test.right))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			constant, err := term.AsConstant[int64](got)
			if err != nil || constant.Value != test.want {
				t.Fatalf("Evaluate = %v, %v; want numeric %d", got, err, test.want)
			}
		})
	}

	for _, invalid := range []term.Term{
		add(term.NewConstant[int64](-1), term.NewConstant[int64](1)),
		add(term.NewConstant[int64](1), term.NewConstant[int64](-1)),
		add(term.NewConstant[int64](math.MaxInt64), term.NewConstant[int64](1)),
		add(add(term.NewConstant[int64](math.MaxInt64-1), term.NewConstant[int64](1)), term.NewConstant[int64](1)),
		add(term.NewConstant[int64](math.MaxInt64-1), add(term.NewConstant[int64](1), term.NewConstant[int64](1))),
		add(term.NewConstant([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}), term.NewConstant[int64](0)),
		add(term.NewConstant("1"), term.NewConstant[int64](1)),
	} {
		if _, err := term.Evaluate(invalid); !errors.Is(err, term.ErrEvaluation) {
			t.Errorf("Evaluate(%s) error = %v; want ErrEvaluation", invalid, err)
		}
	}
}

func TestEvaluateSliceSignedBoundaries(t *testing.T) {
	t.Parallel()

	data := term.NewConstant([]byte{0x00, 0x01, 0x02, 0x03})
	tests := []struct {
		name  string
		start int64
		end   int64
		want  []byte
	}{
		{"positive indexes", 1, 3, []byte{0x01, 0x02}},
		{"negative indexes", -3, -1, []byte{0x01, 0x02}},
		{"zero end", -2, 0, []byte{0x02, 0x03}},
		{"minimum start clamps", math.MinInt64, math.MaxInt64, []byte{0x00, 0x01, 0x02, 0x03}},
		{"maximum start clamps", math.MaxInt64, 0, []byte{}},
		{"minimum end clamps", 0, math.MinInt64, []byte{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			expression := term.NewFunction(term.SliceFunctionName, []term.Term{
				data,
				term.NewConstant(test.start),
				term.NewConstant(test.end),
			})
			got, err := term.Evaluate(expression)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			constant, err := term.AsConstant[[]byte](got)
			if err != nil || !bytes.Equal(constant.Value, test.want) {
				t.Fatalf("Evaluate = %v, %v; want %x", got, err, test.want)
			}
		})
	}
}

func TestEvaluateXorAndNot(t *testing.T) {
	t.Parallel()

	xorTerm := func(left, right term.Term) term.Term {
		return term.NewFunction(term.XorFunctionName, []term.Term{left, right})
	}
	notTerm := func(value term.Term) term.Term {
		return term.NewFunction(term.NotFunctionName, []term.Term{value})
	}
	allOnes := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	tests := []struct {
		name  string
		input term.Term
		want  term.Term
	}{
		{"numeric xor", xorTerm(term.NewConstant[int64](243), term.NewConstant[int64](15)), term.NewConstant[int64](252)},
		{"byte xor preserves width", xorTerm(term.NewConstant([]byte{0xf3, 0x00}), term.NewConstant[int64](15)), term.NewConstant([]byte{0xfc, 0x00})},
		{"mixed xor with numeric result", xorTerm(term.NewConstant[int64](15), term.NewConstant([]byte{0xf3})), term.NewConstant[int64](252)},
		{
			"nested xor",
			xorTerm(xorTerm(term.NewConstant[int64](243), term.NewConstant[int64](15)), term.NewConstant[int64](255)),
			term.NewConstant[int64](3),
		},
		{"numeric not", notTerm(term.NewConstant[int64](0)), term.NewConstant[int64](-1)},
		{"signed numeric not", notTerm(term.NewConstant[int64](243)), term.NewConstant[int64](-244)},
		{"one-byte not", notTerm(term.NewConstant([]byte{0x00})), term.NewConstant([]byte{0xff})},
		{"two-byte not", notTerm(term.NewConstant([]byte{0x00, 0xff})), term.NewConstant([]byte{0xff, 0x00})},
		{
			"eight-byte not",
			notTerm(term.NewConstant([]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			})),
			term.NewConstant([]byte{
				0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
			}),
		},
		{"empty byte not", notTerm(term.NewConstant([]byte{})), term.NewConstant([]byte{})},
		{
			"nested not",
			notTerm(notTerm(term.NewConstant([]byte{0x12, 0x34}))),
			term.NewConstant([]byte{0x12, 0x34}),
		},
		{
			"and preserves an eight-byte first operand",
			term.NewFunction(term.AndFunctionName, []term.Term{
				term.NewConstant(allOnes),
				term.NewConstant[int64](-2),
			}),
			term.NewConstant([]byte{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		},
		{
			"or returns a signed numeric result",
			term.NewFunction(term.OrFunctionName, []term.Term{
				term.NewConstant[int64](-256),
				term.NewConstant([]byte{0xff}),
			}),
			term.NewConstant[int64](-1),
		},
		{
			"xor accepts an all-ones byte pattern",
			term.NewFunction(term.XorFunctionName, []term.Term{
				term.NewConstant(allOnes),
				term.NewConstant[int64](-1),
			}),
			term.NewConstant(make([]byte, 8)),
		},
		{
			"not complements all numeric bits",
			term.NewFunction(term.NotFunctionName, []term.Term{
				term.NewConstant[int64](-1 << 63),
			}),
			term.NewConstant[int64](1<<63 - 1),
		},
		{
			"reverse reinterprets the signed bit pattern",
			term.NewFunction(term.ReverseFuncName, []term.Term{
				term.NewConstant[int64](-2),
			}),
			term.NewConstant[int64](-72057594037927937),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := term.Evaluate(test.input)
			if err != nil {
				t.Fatalf("Evaluate(%s): %v", test.input, err)
			}
			if !got.Equal(test.want) {
				t.Fatalf("Evaluate(%s) = %s, want %s", test.input, got, test.want)
			}
		})
	}
}

func TestEvaluateBitwiseResidualsAndInvalidOperands(t *testing.T) {
	t.Parallel()

	operands := []struct {
		name    string
		value   term.Term
		wantErr error
	}{
		{"variable", term.NewVariable("x"), nil},
		{"ground function", term.NewFunction("opaque", []term.Term{term.NewConstant[int64](1)}), nil},
		{"invalid string", term.NewConstant("text"), term.ErrInvalidType},
	}
	for _, function := range []string{term.AddFunctionName, term.AndFunctionName, term.OrFunctionName, term.XorFunctionName, term.NotFunctionName} {
		for _, operand := range operands {
			if function == term.AddFunctionName && operand.wantErr != nil {
				operand.wantErr = term.ErrEvaluation
			}
			t.Run(function+" "+operand.name, func(t *testing.T) {
				t.Parallel()
				args := []term.Term{operand.value}
				if function != term.NotFunctionName {
					args = append(args, term.NewConstant[int64](1))
				}
				input := term.NewFunction(function, args)
				got, err := term.Evaluate(input)
				if operand.wantErr != nil {
					if !errors.Is(err, operand.wantErr) {
						t.Fatalf("Evaluate(%s) error = %v, want %v", input, err, operand.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("Evaluate(%s): %v", input, err)
				}
				if !got.Equal(input) {
					t.Fatalf("Evaluate(%s) = %s, want symbolic residual", input, got)
				}
			})
		}
	}

	evaluatedOpaque := term.NewFunction("opaque", []term.Term{
		term.NewFunction(term.AddFunctionName, []term.Term{term.NewConstant[int64](1), term.NewConstant[int64](1)}),
	})
	t.Run("rebuilt residual", func(t *testing.T) {
		t.Parallel()
		input := term.NewFunction(term.XorFunctionName, []term.Term{evaluatedOpaque, term.NewConstant[int64](1)})
		want := term.NewFunction(term.XorFunctionName, []term.Term{
			term.NewFunction("opaque", []term.Term{term.NewConstant[int64](2)}),
			term.NewConstant[int64](1),
		})
		got, err := term.Evaluate(input)
		if err != nil {
			t.Fatalf("Evaluate(%s): %v", input, err)
		}
		if !got.Equal(want) {
			t.Fatalf("Evaluate(%s) = %s, want %s", input, got, want)
		}
	})
}

func TestEvaluateBitwiseArity(t *testing.T) {
	t.Parallel()

	for _, name := range []string{term.AndFunctionName, term.OrFunctionName, term.XorFunctionName} {
		_, err := term.Evaluate(term.NewFunction(name, []term.Term{term.NewConstant[int64](1)}))
		if !errors.Is(err, term.ErrBinaryArity) {
			t.Errorf("%s arity error = %v, want ErrBinaryArity", name, err)
		}
	}

	_, err := term.Evaluate(term.NewFunction(term.NotFunctionName, []term.Term{
		term.NewConstant[int64](1),
		term.NewConstant[int64](2),
	}))
	if !errors.Is(err, term.ErrUnaryArity) {
		t.Fatalf("not arity error = %v, want ErrUnaryArity", err)
	}
}

func TestUnifyDoesNotInvertOrNormalizeBitwiseFunctions(t *testing.T) {
	t.Parallel()

	f := term.NewFunction("f", nil)
	g := term.NewFunction("g", nil)
	h := term.NewFunction("h", nil)
	for _, operation := range []term.Term{
		term.NewFunction(term.XorFunctionName, []term.Term{f, g}),
		term.NewFunction(term.NotFunctionName, []term.Term{f}),
	} {
		if _, err := term.Unify(operation, term.NewConstant[int64](1)); err == nil {
			t.Fatalf("Unify(%s, 1) inverted a construct-side operation", operation)
		}
	}

	commutedLeft := term.NewFunction(term.XorFunctionName, []term.Term{f, g})
	commutedRight := term.NewFunction(term.XorFunctionName, []term.Term{g, f})
	if _, err := term.Unify(commutedLeft, commutedRight); err == nil {
		t.Fatal("symbolic xor unified after commutative normalization")
	}

	associatedLeft := term.NewFunction(term.XorFunctionName, []term.Term{
		term.NewFunction(term.XorFunctionName, []term.Term{f, g}),
		h,
	})
	associatedRight := term.NewFunction(term.XorFunctionName, []term.Term{
		f,
		term.NewFunction(term.XorFunctionName, []term.Term{g, h}),
	})
	if _, err := term.Unify(associatedLeft, associatedRight); err == nil {
		t.Fatal("symbolic xor unified after associative normalization")
	}
}

// Vars walks f(a, g(b, a), c) and returns variables in left-to-right
// order with duplicates preserved. Pin this so the prealloc rewrite
// can't silently reorder.
func TestVarsOrder(t *testing.T) {
	t.Parallel()

	a := term.NewVariable("a")
	b := term.NewVariable("b")
	c := term.NewVariable("c")
	tt := term.NewFunction("f", []term.Term{
		a,
		term.NewFunction("g", []term.Term{b, a}),
		c,
	})

	got := term.Vars(tt)
	want := []*term.Variable{a, b, a, c}
	if len(got) != len(want) {
		t.Fatalf("Vars returned %d variables; want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Vars[%d] = %q; want %q", i, got[i].Name, want[i].Name)
		}
	}
}

func TestVarCountAndIsGround(t *testing.T) {
	t.Parallel()

	a := term.NewVariable("a")
	b := term.NewVariable("b")
	c1 := term.NewConstant[int64](1)

	ground := term.NewFunction("h", []term.Term{c1, c1})
	open := term.NewFunction("f", []term.Term{a, term.NewFunction("g", []term.Term{b, a}), c1})

	if term.VarCount(ground) != 0 {
		t.Errorf("VarCount(ground) = %d; want 0", term.VarCount(ground))
	}
	if !term.IsGround(ground) {
		t.Errorf("IsGround(ground) = false; want true")
	}

	if term.VarCount(open) != len(term.Vars(open)) {
		t.Errorf("VarCount(open) = %d; want %d (matches len(Vars))",
			term.VarCount(open), len(term.Vars(open)))
	}
	if term.IsGround(open) {
		t.Errorf("IsGround(open) = true; want false")
	}
}

// SubstBinding's all-variable-keys fast path is now deliberately
// chain-blind: {x->y, y->1} applied to x returns y, not 1. Callers that
// need chain resolution must call ComputeFixpoint first. These cases
// pin the contract so future "fixes" don't silently reintroduce
// chain-following.
func TestSubstBindingFastPath(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	z := term.NewVariable("z")
	one := term.NewConstant[int64](1)

	t.Run("empty binding returns g unchanged", func(t *testing.T) {
		t.Parallel()
		empty := term.NewBinding()
		got := term.SubstBinding(empty, x)
		if got != term.Term(x) {
			t.Errorf("SubstBinding(empty, x) = %v; want x (identity)", got)
		}
	})

	t.Run("single var to constant at top level", func(t *testing.T) {
		t.Parallel()
		b := term.NewBinding()
		b.Set(x, one)
		got := term.SubstBinding(b, x)
		if !got.Equal(one) {
			t.Errorf("SubstBinding({x->1}, x) = %v; want 1", got)
		}
	})

	t.Run("nested function substitution returns rebuilt function", func(t *testing.T) {
		t.Parallel()
		b := term.NewBinding()
		b.Set(x, one)
		input := term.NewFunction("f", []term.Term{x, y})
		got := term.SubstBinding(b, input)
		want := term.NewFunction("f", []term.Term{one, y})
		if !got.Equal(want) {
			t.Errorf("SubstBinding({x->1}, f(x,y)) = %v; want %v", got, want)
		}
	})

	t.Run("unchanged subtree (no var matches) returns identity", func(t *testing.T) {
		t.Parallel()
		b := term.NewBinding()
		b.Set(z, one)
		input := term.NewFunction("f", []term.Term{x, y})
		got := term.SubstBinding(b, input)
		if got != term.Term(input) {
			t.Errorf("SubstBinding({z->1}, f(x,y)) should return the original pointer; got %v", got)
		}
	})

	t.Run("chained binding without fixpoint returns intermediate", func(t *testing.T) {
		t.Parallel()
		// {x->y, y->1} applied to x: fast path does not follow chains.
		b := term.NewBinding()
		b.Set(x, y)
		b.Set(y, one)
		got := term.SubstBinding(b, x)
		if !got.Equal(y) {
			t.Errorf("SubstBinding({x->y, y->1}, x) = %v; want y (fast path is chain-blind)", got)
		}
	})

	t.Run("chained binding with ComputeFixpoint resolves", func(t *testing.T) {
		t.Parallel()
		b := term.NewBinding()
		b.Set(x, y)
		b.Set(y, one)
		fp := b.ComputeFixpoint()
		got := term.SubstBinding(fp, x)
		if !got.Equal(one) {
			t.Errorf("SubstBinding(ComputeFixpoint({x->y, y->1}), x) = %v; want 1", got)
		}
	})

	t.Run("non-variable key falls back to per-binding Replace", func(t *testing.T) {
		t.Parallel()
		// Map a function term to a variable; the all-variables fast
		// path must be skipped so Replace can match the function.
		fxy := term.NewFunction("f", []term.Term{x, y})
		b := term.NewBinding()
		b.Set(fxy, z)
		got := term.SubstBinding(b, term.NewFunction("g", []term.Term{fxy}))
		want := term.NewFunction("g", []term.Term{z})
		if !got.Equal(want) {
			t.Errorf("SubstBinding({f(x,y)->z}, g(f(x,y))) = %v; want %v", got, want)
		}
	})
}

// TestEvaluateCatKeepsUnevaluableCallsSymbolic checks that a ground cat
// whose field holds a call that cannot be evaluated stays symbolic, as the
// other operations do, while an invalid constant is an evaluation error.
func TestEvaluateCatKeepsUnevaluableCallsSymbolic(t *testing.T) {
	t.Parallel()

	field := func(kind term.FormatType, value term.Term) term.Term {
		return term.NewFunction(string(kind), []term.Term{value})
	}
	cat := func(fields ...term.Term) term.Term { return term.NewFunction(term.CatFunctionName, fields) }
	opaque := term.NewFunction("opaque", []term.Term{term.NewConstant[int64](1)})
	pair := term.NewFunction(term.PairFunctionName, []term.Term{term.NewConstant([]byte{1}), term.NewConstant([]byte{2})})
	for _, input := range []term.Term{
		cat(field(term.FormatByteType, opaque)),
		cat(field(term.FormatByteType, term.NewConstant([]byte{1})), field(term.FormatByteType, opaque)),
		cat(field(term.FormatByteType, pair)),
		cat(formatField(term.FormatIntType, term.NewVariable("x"), 1)),
	} {
		got, err := term.Evaluate(input)
		if err != nil || !got.Equal(input) {
			t.Errorf("Evaluate(%s) = %v, %v; want symbolic residual", input, got, err)
		}
	}
	for _, invalid := range []term.Term{
		cat(field(term.FormatIntType, term.NewConstant("text"))),
		cat(formatField(term.FormatIntType, term.NewConstant[int64](256), 1)),
	} {
		if got, err := term.Evaluate(invalid); !errors.Is(err, term.ErrEvaluation) {
			t.Errorf("Evaluate(%s) = %v, %v; want an evaluation error", invalid, got, err)
		}
	}
	// A field that is not a format function is an error in any position.
	for _, malformed := range []term.Term{
		cat(field(term.FormatByteType, opaque), term.NewVariable("y")),
		cat(term.NewVariable("y"), field(term.FormatByteType, opaque)),
	} {
		if got, err := term.Evaluate(malformed); !errors.Is(err, term.ErrInvalidFormatFunction) {
			t.Errorf("Evaluate(%s) = %v, %v; want %v", malformed, got, err, term.ErrInvalidFormatFunction)
		}
	}
}

// TestUnifyBindsRepeatedVariablesConsistently checks that a variable that
// occurs several times in a pattern must take the same value at each
// occurrence: across arguments, nested, as a format field, and when
// variables of both sides are bound to each other. A variable that would
// occur in its own value through another variable has no unifier.
func TestUnifyBindsRepeatedVariablesConsistently(t *testing.T) {
	t.Parallel()

	x, y, z := term.NewVariable("x"), term.NewVariable("y"), term.NewVariable("z")
	a, b := term.NewConstant("a"), term.NewConstant("b")
	pair := func(l, r term.Term) term.Term { return term.NewFunction(term.PairFunctionName, []term.Term{l, r}) }
	fn := func(name string, args ...term.Term) term.Term { return term.NewFunction(name, args) }
	field := func(v term.Term) term.Term {
		return fn(term.CatFunctionName, fn("byte", v))
	}
	five, six := term.NewConstant([]byte{0x05}), term.NewConstant([]byte{0x06})

	for _, tc := range []struct {
		name            string
		pattern, target term.Term
		want            map[term.Term]term.Term // nil: no unifier
	}{
		{"across arguments, equal", pair(x, x), pair(a, a), map[term.Term]term.Term{x: a}},
		{"across arguments, different", pair(x, x), pair(a, b), nil},
		{"nested, equal", fn("f", x, fn("g", x)), fn("f", a, fn("g", a)), map[term.Term]term.Term{x: a}},
		{"nested, different", fn("f", x, fn("g", x)), fn("f", a, fn("g", b)), nil},
		{"format field, equal", pair(x, field(x)), pair(five, five), map[term.Term]term.Term{x: five}},
		{"format field, different", pair(x, field(x)), pair(six, five), nil},
		{"pattern against pattern", pair(x, x), pair(y, a), map[term.Term]term.Term{x: a, y: a}},
		{"variables bound to each other", fn("t", x, y, x), fn("t", y, x, a), map[term.Term]term.Term{x: a, y: a}},
		{"chain of variables", fn("t", x, z, y, x), fn("t", y, x, z, a), map[term.Term]term.Term{x: a, y: a, z: a}},
		{"cycle through a bound variable", pair(x, y), pair(y, fn("f", x)), nil},
		{"cycle through another instance of a variable", x, fn("f", term.NewVariable("x")), nil},
	} {
		got, err := term.Unify(tc.pattern, tc.target)
		if tc.want == nil {
			if err == nil {
				t.Errorf("%s: Unify(%s, %s) = %s, want no unifier", tc.name, tc.pattern, tc.target, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Unify(%s, %s): %v", tc.name, tc.pattern, tc.target, err)
			continue
		}
		for v, want := range tc.want {
			if value, ok := got.Get(v); !ok || !value.Equal(want) {
				t.Errorf("%s: Unify(%s, %s) = %s, want %s bound to %s", tc.name, tc.pattern, tc.target, got, v, want)
			}
		}
	}
}

// TestUnifyAllBindsAcrossTerms checks that UnifyAll uses one binding for
// all pairs of terms.
func TestUnifyAllBindsAcrossTerms(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	a, b := term.NewConstant("a"), term.NewConstant("b")
	if _, err := term.UnifyAll([]term.Term{x, x}, []term.Term{a, b}); err == nil {
		t.Fatal("UnifyAll bound x to two different values")
	}
	got, err := term.UnifyAll([]term.Term{x, x}, []term.Term{a, a})
	if err != nil {
		t.Fatalf("UnifyAll: %v", err)
	}
	if value, ok := got.Get(x); !ok || !value.Equal(a) {
		t.Fatalf("UnifyAll = %s, want x bound to %s", got, a)
	}
}

// TestUnifyAllDoesNotCopyGroundValues checks that binding variables to
// function terms allocates no more than binding them to constants: the
// values bound so far are ground, so a new binding must not copy them.
// It does not run in parallel, since AllocsPerRun counts allocations of
// the whole process.
func TestUnifyAllDoesNotCopyGroundValues(t *testing.T) {
	const n = 16
	vars := make([]term.Term, n)
	constants := make([]term.Term, n)
	pairs := make([]term.Term, n)
	for i := range n {
		vars[i] = term.NewVariable("x" + strconv.Itoa(i))
		c := term.NewConstant("c" + strconv.Itoa(i))
		constants[i] = c
		pairs[i] = term.NewFunction(term.PairFunctionName, []term.Term{c, c})
	}
	allocs := func(values []term.Term) float64 {
		return testing.AllocsPerRun(20, func() {
			if _, err := term.UnifyAll(vars, values); err != nil {
				t.Fatal(err)
			}
		})
	}
	if got, want := allocs(pairs), allocs(constants); got > want {
		t.Fatalf("UnifyAll with %d pairs: %v allocations, with %d constants: %v", n, got, n, want)
	}
}

func TestUnifyAllLengthMismatch(t *testing.T) {
	x, a, b := term.NewVariable("x"), term.NewConstant("a"), term.NewConstant("b")
	for _, tc := range []struct {
		name        string
		left, right []term.Term
	}{
		{"right_empty", []term.Term{x}, nil},
		{"left_empty", nil, []term.Term{a}},
		{"right_longer", []term.Term{x}, []term.Term{a, b}},
		{"left_longer", []term.Term{x, x}, []term.Term{a}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("panic instead of length error: %v", p)
				}
			}()
			got, err := term.UnifyAll(tc.left, tc.right)
			if got != nil || !errors.Is(err, term.ErrNameOrArgMismatch) {
				t.Errorf("UnifyAll = %v, %v; want nil, ErrNameOrArgMismatch", got, err)
			}
		})
	}
	if b, err := term.UnifyAll(nil, nil); err != nil || b == nil || b.Size() != 0 {
		t.Fatalf("equal empty slices = %v,%v", b, err)
	}
}
