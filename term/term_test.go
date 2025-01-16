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
	"testing"

	"github.com/specmon/specmon/term"
)

func TestCompatible(t *testing.T) {
	t.Parallel()

	b1 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("x"): term.NewConstant(1),
		term.NewVariable("y"): term.NewConstant(2),
	})
	b2 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("y"): term.NewConstant(2),
		term.NewVariable("z"): term.NewConstant(3),
	})
	b3 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("y"): term.NewConstant(3),
		term.NewVariable("z"): term.NewConstant(3),
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
		term.NewVariable("x"): term.NewConstant(1),
		term.NewVariable("y"): term.NewConstant(2),
	})
	b2 := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("a"): term.NewConstant(3),
		term.NewVariable("b"): term.NewConstant(4),
	})

	expect := term.BindingFromMap(map[term.Term]term.Term{
		term.NewVariable("x"): term.NewConstant(1),
		term.NewVariable("y"): term.NewConstant(2),
		term.NewVariable("a"): term.NewConstant(3),
		term.NewVariable("b"): term.NewConstant(4),
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
			term.NewConstant[int](1),
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("x"): term.NewConstant(1),
			}),
			false,
		},
		{
			// unify(f(1, x), f(y, 2)) | [ x -> 2, y -> 1 ]
			term.NewFunction("f", []term.Term{term.NewConstant[int](1), term.NewVariable("x")}),
			term.NewFunction("f", []term.Term{term.NewVariable("y"), term.NewConstant[int](2)}),
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("x"): term.NewConstant(2),
				term.NewVariable("y"): term.NewConstant[int](1),
			}),
			false,
		},
		{
			// unify(f(x, y), f"y, x)) | [ x -> x, y -> x ]
			term.NewFunction("f", []term.Term{term.NewVariable("x"), term.NewVariable("y")}),
			term.NewFunction("f", []term.Term{term.NewVariable("y"), term.NewVariable("x")}),
			term.BindingFromMap(map[term.Term]term.Term{
				term.NewVariable("x"): term.NewVariable("x"),
				term.NewVariable("y"): term.NewVariable("x"),
			}),
			false,
		},
		{
			// unify(cat(int(11)), 0x0b00000000000000) | [ ]
			term.NewFunction("cat", []term.Term{term.NewFunction("int", []term.Term{term.NewConstant[int](11)})}),
			term.NewConstant[[]byte]([]byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			term.NewBinding(),
			false,
		},
		{
			// unify(cat(int(11)), 0x0b00000000000000) | [ ]
			term.NewFunction("cat", []term.Term{term.NewFunction("int", []term.Term{term.NewConstant[int](11)})}),
			term.NewConstant[[]byte]([]byte{0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			term.NewBinding(),
			false,
		},
		{
			// unify(cat(int(length, 1), int(a, length), byte(b, length)), 0x0203000400) | [ length -> 2, a -> 3, b -> 0x0400 ]
			term.NewFunction("cat", []term.Term{
				term.NewFunction("int", []term.Term{
					term.NewVariable("length"),
					term.NewConstant[int](1),
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
				term.NewVariable("length"): term.NewConstant[int](2),
				term.NewVariable("a"):      term.NewConstant[int](3),
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
					term.NewConstant[int](40),
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
			term.NewConstant[int](1),
			term.NewConstant[int](1),
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
				term.NewConstant[int](1),
				term.NewConstant[int](1),
			}),
			term.NewConstant[int](2),
			false,
		},
		{
			// evaluate(add('x', '1')) | add('x', '2')
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewVariable("x"),
				term.NewConstant[int](1),
			}),
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewVariable("x"),
				term.NewConstant[int](1),
			}),
			false,
		},
		{
			// evaluate(add(add('1', '2'), '1')) | '4'
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewFunction(term.AddFunctionName, []term.Term{
					term.NewConstant[int](1),
					term.NewConstant[int](2),
				}),
				term.NewConstant[int](1),
			}),
			term.NewConstant[int](4),
			false,
		},
		{
			// evaluate(add(cat(byte('0x01'), byte('0x00'))), '1') | 0x0100 + 1 = 0x0200
			term.NewFunction(term.AddFunctionName, []term.Term{
				term.NewFunction(term.CatFunctionName, []term.Term{
					term.NewFunction(string(term.FormatByteType), []term.Term{
						term.NewConstant[[]byte]([]byte{0x01}),
					}),
					term.NewFunction(string(term.FormatByteType), []term.Term{
						term.NewConstant[[]byte]([]byte{0x00}),
					}),
				}),
				term.NewConstant[int](1),
			}),
			term.NewConstant[[]byte]([]byte{0x02, 0x00}),
			false,
		},
		{
			// evaluate(and('0xf3', 248)) | 0xf0
			term.NewFunction(term.AndFunctionName, []term.Term{
				term.NewConstant[[]byte]([]byte{0xf3}),
				term.NewConstant[int](248),
			}),
			term.NewConstant[[]byte]([]byte{0xf0}),
			false,
		},
		{
			// evaluate(and(243, 248)) | 243
			term.NewFunction(term.AndFunctionName, []term.Term{
				term.NewConstant[int](243),
				term.NewConstant[int](248),
			}),
			term.NewConstant[int](240),
			false,
		},
		{
			// evaluate(or(and('0x30', '127'), '64')) | 0x70
			term.NewFunction(term.OrFunctionName, []term.Term{
				term.NewFunction(term.AndFunctionName, []term.Term{
					term.NewConstant[[]byte]([]byte{0x30}),
					term.NewConstant[int](127),
				}),
				term.NewConstant[int](64),
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
						term.NewConstant[int](248),
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
							term.NewConstant[int](127),
						}),
						term.NewConstant[int](64),
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
