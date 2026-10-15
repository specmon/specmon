// Copyright (C) 2026 CISPA Helmholtz Center for Information Security
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

package parser_test

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/specmon/specmon/parser"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// parseRule parses a theory with one rule that has the given conclusion.
func parseRule(t *testing.T, conclusion string) ([]*rule.Rule, error) {
	t.Helper()
	source := fmt.Sprintf("theory T\nbegin\n\nrule R:\n  [ State(x, y) ]\n  -->\n  [ %s ]\n\nend\n", conclusion)
	path := filepath.Join(t.TempDir(), "rule.spthy")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("write specification: %v", err)
	}
	return parser.ParseFile(context.Background(), path, nil)
}

// TestParseMacroParametersAreLocal checks that the parameters of a macro do
// not capture variables of the same names in the rule that applies it, and
// that a macro head must be a function of distinct variables.
func TestParseMacroParametersAreLocal(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, macro, conclusion, want string
	}{
		{"swapped names", "m(x, y) = cat(byte(x), byte(y))", "Next(m(y, x))", "cat(byte(y), byte(x))"},
		{"name inside an argument", "m(x) = cat(byte(x))", "Next(m(h(x)))", "cat(byte(h(x)))"},
		{"nested application", "m(x, y) = <x, y>", "Next(m(m(y, x), x))", "<<y, x>, x>"},
		{"repeated parameter", "m(x, x) = cat(byte(x))", "Next(m(y, x))", ""},
		{"constant parameter", "m(x, '1') = cat(byte(x))", "Next(m(y, '1'))", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source := fmt.Sprintf("theory T\nbegin\n\nmacros: %s\n\nrule R:\n  [ State(x, y) ]\n  -->\n  [ %s ]\n\nend\n", test.macro, test.conclusion)
			path := filepath.Join(t.TempDir(), "macro.spthy")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatalf("write specification: %v", err)
			}
			rules, err := parser.ParseFile(context.Background(), path, nil)
			if test.want == "" {
				if err == nil || !strings.Contains(err.Error(), "the parameters must be distinct variables") {
					t.Fatalf("ParseFile error = %v, want an invalid macro head", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			if len(rules) != 1 || len(rules[0].RHS) != 1 || len(rules[0].RHS[0].Args) != 1 {
				t.Fatalf("unexpected parsed rules: %v", rules)
			}
			if got := rules[0].RHS[0].Args[0].String(); got != test.want {
				t.Fatalf("expanded macro = %s, want %s", got, test.want)
			}
		})
	}
}

func TestParseConstructSideXorAndNot(t *testing.T) {
	t.Parallel()

	rules, err := parseRule(t, "Next(x XOR y, not(x))")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 || len(rules[0].RHS) != 1 || len(rules[0].RHS[0].Args) != 2 {
		t.Fatalf("unexpected parsed rules: %v", rules)
	}

	xor, err := term.AsFunction(rules[0].RHS[0].Args[0])
	if err != nil || xor.Name != term.XorFunctionName || len(xor.Args) != term.BinaryArity {
		t.Fatalf("parsed xor = %v, error = %v", xor, err)
	}
	not, err := term.AsFunction(rules[0].RHS[0].Args[1])
	if err != nil || not.Name != term.NotFunctionName || len(not.Args) != 1 {
		t.Fatalf("parsed not = %v, error = %v", not, err)
	}
}

func TestParseInt64Boundaries(t *testing.T) {
	t.Parallel()

	rules, err := parseRule(t, "Values('0', '-1', '9007199254740993', '9223372036854775807', %12)")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	want := []int64{0, -1, 9007199254740993, math.MaxInt64, 12}
	for i, arg := range rules[0].RHS[0].Args {
		constant, err := term.AsConstant[int64](arg)
		if err != nil || constant.Value != want[i] {
			t.Fatalf("argument %d = %v, %v; want %d", i, arg, err, want[i])
		}
	}

	for _, value := range []string{"'9223372036854775808'", "'-9223372036854775809'", "%9223372036854775808"} {
		_, err := parseRule(t, "Values("+value+")")
		if err == nil || !strings.Contains(err.Error(), "rule.spthy:7:") {
			t.Fatalf("ParseFile(%s) error = %v, want an error at line 7", value, err)
		}
	}
}
