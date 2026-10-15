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

package monitor

import (
	"slices"
	"strings"
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

const (
	admissionTestRule    = "AdmissionTest"
	admissionTestCall    = "admissionTestCall"
	admissionTestOther   = "admissionTestOther"
	admissionTestPremise = "AdmissionTestPremise"
	admissionTestResult  = "AdmissionTestResult"
	admissionTestAction  = "AdmissionTestAction"
)

// admissionCase is a rule set and the parts that the error of NewMonitor
// must contain. No parts means that the rules are admitted. An admitted
// rule set has a warning that contains the parts of warn, or none.
type admissionCase struct {
	name  string
	rules []*rule.Rule
	want  []string
	warn  []string
}

func runAdmissionCases(t *testing.T, cases []admissionCase) {
	t.Helper()
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewMonitor(test.rules)
			if len(test.want) == 0 {
				if err != nil {
					t.Fatalf("NewMonitor: %v", err)
				}
				warnings := Warnings(test.rules)
				if len(test.warn) == 0 && len(warnings) > 0 {
					t.Fatalf("warnings = %q, want none", warnings)
				}
				if len(test.warn) > 0 && !slices.ContainsFunc(warnings, func(w string) bool {
					return !slices.ContainsFunc(test.warn, func(part string) bool { return !strings.Contains(w, part) })
				}) {
					t.Fatalf("warnings = %q, want one with %q", warnings, test.warn)
				}
				return
			}
			if err == nil {
				t.Fatalf("NewMonitor admitted the rules, want an error with %q", test.want)
			}
			for _, part := range test.want {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("NewMonitor error = %q, want %q", err, part)
				}
			}
		})
	}
}

func admissionCall(result term.Term, args ...term.Term) term.Term {
	return term.NewFunction(term.PairFunctionName, []term.Term{term.NewFunction(admissionTestCall, args), result})
}

func admissionFunction(name string, args ...term.Term) *term.Function {
	return term.NewFunction(name, args)
}

func admissionField(name term.FormatType, args ...term.Term) term.Term {
	return admissionFunction(string(name), args...)
}

func admissionCat(fields ...term.Term) term.Term {
	return admissionFunction(term.CatFunctionName, fields...)
}

func TestNewMonitorChecksRestrictionArity(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	one := term.NewConstant("1")
	var cases []admissionCase
	for _, name := range []string{restrictionEq, restrictionEqual, restrictionNeq, restrictionNotEqual, restrictionUnequal} {
		withOperands := func(operands ...term.Term) []*rule.Rule {
			return []*rule.Rule{triggerRule(admissionTestRule, nil, nil, []*rule.Fact{rule.NewFact(name, operands, rule.LinearFact)},
				admissionCall(x))}
		}
		cases = append(cases,
			admissionCase{name: name + "/two operands", rules: withOperands(x, one)},
			admissionCase{name: name + "/one operand", rules: withOperands(x), want: []string{admissionTestRule, name, "1 operands"}},
			admissionCase{name: name + "/three operands", rules: withOperands(x, one, one), want: []string{admissionTestRule, name, "3 operands"}},
		)
	}
	runAdmissionCases(t, cases)
}

func TestNewMonitorChecksRewriteOutputs(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	unit := term.NewFunction(term.PairFunctionName, nil)
	withOutput := func(args ...term.Term) []*rule.Rule {
		return []*rule.Rule{triggerRule(admissionTestRule, nil, nil, []*rule.Fact{rule.NewFact(rule.RewriteEventName, args, rule.LinearFact)},
			admissionCall(x))}
	}
	runAdmissionCases(t, []admissionCase{
		{name: "pair with a call", rules: withOutput(term.NewFunction(term.PairFunctionName, []term.Term{admissionFunction(admissionTestOther, x), unit}))},
		{name: "pair with a variable", rules: withOutput(term.NewFunction(term.PairFunctionName, []term.Term{x, unit}))},
		{name: "no argument", rules: withOutput(), want: []string{admissionTestRule, rule.RewriteEventName, "0 arguments"}},
		{name: "two arguments", rules: withOutput(x, x), want: []string{admissionTestRule, "2 arguments"}},
		{name: "call", rules: withOutput(admissionFunction(admissionTestOther, x)), want: []string{admissionTestRule, "does not emit a pair"}},
		{name: "variable", rules: withOutput(x), want: []string{admissionTestRule, "does not emit a pair"}},
		{name: "unit", rules: withOutput(unit), want: []string{admissionTestRule, "does not emit a pair"}},
	})
}

func TestNewMonitorChecksFunctionArity(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	one := term.NewConstant[int64](1)
	withTerm := func(t term.Term) []*rule.Rule {
		return []*rule.Rule{triggerRule(admissionTestRule, nil, []*rule.Fact{linearFact(admissionTestResult, t)}, nil, admissionCall(x))}
	}

	cases := []admissionCase{
		{name: "cat without fields", rules: withTerm(admissionCat())},
		{name: "cat fields", rules: withTerm(admissionCat(admissionField(term.FormatIntType, x), admissionField(term.FormatByteType, x, one),
			admissionField(term.FormatStringType, x)))},
		{name: "cat with a constant", rules: withTerm(admissionCat(one)), want: []string{admissionTestRule, "is not an int, byte or string field"}},
		{name: "cat with a variable", rules: withTerm(admissionCat(x)), want: []string{"is not an int, byte or string field"}},
		{
			name: "cat with another function", rules: withTerm(admissionCat(admissionFunction(admissionTestOther, x))),
			want: []string{"is not an int, byte or string field"},
		},
		{name: "field without arguments", rules: withTerm(admissionCat(admissionField(term.FormatByteType))), want: []string{"is not an int, byte or string field"}},
		{
			name: "field with three arguments", rules: withTerm(admissionCat(admissionField(term.FormatIntType, x, one, one))),
			want: []string{"is not an int, byte or string field"},
		},
		{
			name: "nested", rules: withTerm(admissionFunction(admissionTestOther, admissionFunction(term.NotFunctionName, x, x))),
			want: []string{admissionTestRule, "not(x, x) has 2 arguments, want 1"},
		},
	}
	cases = append(cases, admissionCase{
		name: "in a hint",
		rules: []*rule.Rule{hintRule(admissionTestRule, []*rule.Fact{linearFact(admissionTestPremise, x)}, nil, nil,
			admissionCall(admissionFunction(term.NotFunctionName, x, x)))},
		want: []string{admissionTestRule, "not(x, x) has 2 arguments, want 1"},
	})
	// The arities are written out here, not read from evaluableArity.
	for _, function := range []struct {
		name  string
		arity int
	}{
		{term.AddFunctionName, 2},
		{term.AndFunctionName, 2},
		{term.OrFunctionName, 2},
		{term.XorFunctionName, 2},
		{term.NotFunctionName, 1},
		{term.ReverseFuncName, 1},
		{term.SliceFunctionName, 3},
	} {
		name, arity := function.name, function.arity
		args := []term.Term{x, x, x, x}
		cases = append(cases,
			admissionCase{name: name + "/right arity", rules: withTerm(admissionFunction(name, args[:arity]...))},
			admissionCase{
				name: name + "/one more", rules: withTerm(admissionFunction(name, args[:arity+1]...)),
				want: []string{admissionTestRule, name},
			},
			admissionCase{
				name: name + "/one less", rules: withTerm(admissionFunction(name, args[:arity-1]...)),
				want: []string{admissionTestRule, name},
			},
		)
	}
	runAdmissionCases(t, cases)
}

func TestNewMonitorChecksVariableBinding(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	r := term.NewVariable("r")
	l := term.NewVariable("l")
	two := term.NewConstant[int64](2)
	premise := func(args ...term.Term) *rule.Fact { return linearFact(admissionTestPremise, args...) }
	result := func(args ...term.Term) []*rule.Fact { return []*rule.Fact{linearFact(admissionTestResult, args...)} }
	add := func(a, b term.Term) term.Term { return admissionFunction(term.AddFunctionName, a, b) }
	trigger := func(lhs []*rule.Fact, rhs []*rule.Fact, triggers ...term.Term) []*rule.Rule {
		return []*rule.Rule{triggerRule(admissionTestRule, lhs, rhs, nil, triggers...)}
	}
	unbound := func(v string, where string) []string {
		return []string{admissionTestRule, "variable " + v + " of its " + where, "cannot be bound by matching"}
	}
	unmatchable := func(v string) []string {
		return []string{admissionTestRule, "variable " + v + " is not bound when matching needs its value", "matches only terms that contain such a subterm unevaluated"}
	}

	runAdmissionCases(t, []admissionCase{
		{name: "bound by a premise", rules: trigger([]*rule.Fact{premise(x)}, result(x), admissionCall(r))},
		{name: "bound by the trigger", rules: trigger(nil, result(x, r), admissionCall(r, x))},
		{name: "unbound conclusion", rules: trigger(nil, result(y), admissionCall(r, x)), want: unbound("y", "conclusions")},
		{
			name: "unbound action",
			rules: []*rule.Rule{triggerRule(admissionTestRule, nil, nil, []*rule.Fact{linearFact(admissionTestAction, y)},
				admissionCall(r))},
			want: unbound("y", "actions"),
		},
		{
			name: "unbound restriction operand",
			rules: []*rule.Rule{triggerRule(admissionTestRule, nil, nil, []*rule.Fact{rule.NewFact(restrictionEq, []term.Term{y, r}, rule.LinearFact)},
				admissionCall(r))},
			want: unbound("y", "actions"),
		},
		{
			name:  "premise with a construction-only function",
			rules: trigger([]*rule.Fact{premise(add(x, two))}, nil, admissionCall(r, x)),
			want:  []string{admissionTestRule, "premise", "contains add(x, 2), which is only evaluated, never parsed"},
		},
		{
			name:  "only below an evaluated function in the trigger",
			rules: trigger(nil, result(x), admissionCall(r, add(x, two))),
			warn:  unmatchable("x"),
		},
		{
			name:  "only in a one-argument field before the last field",
			rules: trigger(nil, result(x), admissionCall(r, admissionCat(admissionField(term.FormatByteType, x), admissionField(term.FormatByteType, y, two)))),
			warn:  unmatchable("x"),
		},
		{
			name:  "only in a one-argument string field before the last field",
			rules: trigger(nil, result(x), admissionCall(r, admissionCat(admissionField(term.FormatStringType, x), admissionField(term.FormatByteType, y)))),
			warn:  unmatchable("x"),
		},
		{name: "one-argument last field", rules: trigger(nil, result(x, y), admissionCall(r, admissionCat(admissionField(term.FormatByteType, y, two), admissionField(term.FormatByteType, x))))},
		{
			name:  "int field without length before the last field",
			rules: trigger(nil, result(x), admissionCall(r, admissionCat(admissionField(term.FormatIntType, x), admissionField(term.FormatByteType, y)))),
		},
		{name: "one-argument int last field", rules: trigger(nil, result(x), admissionCall(r, admissionCat(admissionField(term.FormatByteType, y, two), admissionField(term.FormatIntType, x))))},
		{name: "field with a length", rules: trigger(nil, result(x), admissionCall(r, admissionCat(admissionField(term.FormatByteType, x, two), admissionField(term.FormatByteType, y))))},
		{
			name:  "one-argument field with a constant before the last field",
			rules: trigger(nil, result(x), admissionCall(r, admissionCat(admissionField(term.FormatByteType, term.NewConstant([]byte{1})), admissionField(term.FormatByteType, x)))),
		},
		{
			name:  "one-argument fields in a constructed cat",
			rules: trigger([]*rule.Fact{premise(x, y)}, result(admissionCat(admissionField(term.FormatByteType, x), admissionField(term.FormatByteType, y))), admissionCall(r)),
		},
		{
			name:  "one-argument field before the last field bound by a premise",
			rules: trigger([]*rule.Fact{premise(x)}, result(x), admissionCall(r, admissionCat(admissionField(term.FormatByteType, x), admissionField(term.FormatByteType, y)))),
		},
		{
			// Matching substitutes the premise bindings before it evaluates
			// a pattern, not those of the pattern's other arguments.
			name:  "one-argument field before the last field bound by another argument",
			rules: trigger(nil, result(x, y), admissionCall(r, x, admissionCat(admissionField(term.FormatByteType, x), admissionField(term.FormatByteType, y)))),
			warn:  unmatchable("x"),
		},
		{name: "below an evaluated function, bound by a premise", rules: trigger([]*rule.Fact{premise(x)}, result(x), admissionCall(r, add(x, two)))},
		{
			name:  "below an evaluated function, bound by another argument",
			rules: trigger(nil, result(x), admissionCall(r, x, add(x, two))),
			warn:  unmatchable("x"),
		},
		{
			name:  "a length does not bind",
			rules: trigger(nil, result(l), admissionCall(r, admissionCat(admissionField(term.FormatStringType, x, l)))),
			warn:  unmatchable("l"),
		},
		{
			name: "a length bound by an earlier field",
			rules: trigger(nil, result(x, l),
				admissionCall(r, admissionCat(admissionField(term.FormatIntType, l, term.NewConstant[int64](8)), admissionField(term.FormatStringType, x, l)))),
		},
		{
			name:  "unbound conclusion beside a variable only below an evaluated function",
			rules: trigger(nil, result(x, y), admissionCall(r, add(x, two))),
			want:  unbound("y", "conclusions"),
		},
		{name: "epsilon rule", rules: []*rule.Rule{epsilonRule(admissionTestRule, []*rule.Fact{premise(x)}, result(x), nil)}},
		{
			name:  "epsilon rule with an unbound conclusion",
			rules: []*rule.Rule{epsilonRule(admissionTestRule, []*rule.Fact{premise(x)}, result(y), nil)},
			want:  unbound("y", "conclusions"),
		},
	})
}

func TestNewMonitorChecksHintAlternatives(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	r := term.NewVariable("r")
	s := term.NewVariable("s")
	ready := linearFact(admissionTestPremise, y)
	other := term.NewFunction(term.PairFunctionName, []term.Term{admissionFunction(admissionTestOther, x), s})
	hinted := func(rhs []*rule.Fact, hints ...term.Term) []*rule.Rule {
		return []*rule.Rule{hintRule(admissionTestRule, []*rule.Fact{ready}, rhs, nil, hints...)}
	}

	runAdmissionCases(t, []admissionCase{
		{name: "premise variable", rules: hinted([]*rule.Fact{linearFact(admissionTestResult, y)}, admissionCall(r, x), admissionCall(s))},
		{name: "bound by every hint", rules: hinted([]*rule.Fact{linearFact(admissionTestResult, x)}, admissionCall(r, x), other)},
		{
			name:  "bound by one hint only",
			rules: hinted([]*rule.Fact{linearFact(admissionTestResult, r)}, admissionCall(r, x), other),
			want:  []string{admissionTestRule, "variable r of its conclusions", "when hint " + other.String() + " matches"},
		},
		{name: "evaluated function bound by the premise", rules: hinted(nil, admissionCall(r, admissionFunction(term.NotFunctionName, y)))},
		{
			name:  "evaluated function not bound by the premise",
			rules: hinted(nil, admissionCall(r, admissionFunction(term.NotFunctionName, x))),
			warn:  []string{admissionTestRule, "variable x is not bound", "when hint " + admissionCall(r, admissionFunction(term.NotFunctionName, x)).String() + " matches"},
		},
	})
}

func TestNewMonitorChecksNativeTriggers(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	z := term.NewVariable("z")
	two := term.NewConstant[int64](2)
	first := admissionCall(x)
	second := term.NewFunction(term.PairFunctionName, []term.Term{admissionFunction(admissionTestOther), y})
	native := func(lhs, rhs []*rule.Fact, triggers ...term.Term) []*rule.Rule {
		return []*rule.Rule{triggerRule(admissionTestRule, lhs, rhs, nil, triggers...)}
	}
	unparsed := linearFact(admissionTestPremise, admissionCat(admissionField(term.FormatByteType, x), admissionField(term.FormatByteType, z)))

	runAdmissionCases(t, []admissionCase{
		{name: "conclusion bound by the last trigger", rules: native(nil, []*rule.Fact{linearFact(admissionTestResult, x, y)}, first, second)},
		{
			name:  "unbound conclusion",
			rules: native(nil, []*rule.Fact{linearFact(admissionTestResult, z)}, first, second),
			want:  []string{admissionTestRule, "variable z of its conclusions", "cannot be bound by matching"},
		},
		{
			name:  "premise parsed with the binding of a trigger",
			rules: native([]*rule.Fact{unparsed}, nil, first, second),
			want:  []string{admissionTestRule, "variable x of premise", "cannot be parsed from a fact"},
		},
		{
			name:  "later trigger bound by an earlier trigger",
			rules: native(nil, nil, first, term.NewFunction(term.PairFunctionName, []term.Term{admissionFunction(admissionTestOther, admissionFunction(term.AddFunctionName, x, two)), y})),
			warn: []string{
				admissionTestRule, "variable x is not bound",
				"when trigger " + term.NewFunction(term.PairFunctionName, []term.Term{admissionFunction(admissionTestOther, admissionFunction(term.AddFunctionName, x, two)), y}).String() + " arrives first",
			},
		},
	})
}

// TestNewMonitorChecksPremiseParsing checks that a premise can be matched
// against the facts on its own, without the bindings of a trigger, a hint,
// another premise or another argument of the same premise.
func TestNewMonitorChecksPremiseParsing(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	y := term.NewVariable("y")
	l := term.NewVariable("l")
	rest := term.NewVariable("rest")
	r := term.NewVariable("r")
	premise := func(args ...term.Term) *rule.Fact { return linearFact(admissionTestPremise, args...) }
	other := func(args ...term.Term) *rule.Fact { return linearFact(admissionTestResult, args...) }
	trigger := func(lhs ...*rule.Fact) []*rule.Rule {
		return []*rule.Rule{triggerRule(admissionTestRule, lhs, nil, nil, admissionCall(r, x))}
	}
	hinted := func(lhs ...*rule.Fact) []*rule.Rule {
		return []*rule.Rule{hintRule(admissionTestRule, lhs, nil, nil, admissionCall(r, x))}
	}
	unparsed := func(v string) []string {
		return []string{admissionTestRule, "variable " + v + " of premise", "cannot be parsed from a fact"}
	}
	constructionOnly := func(name string) []string {
		return []string{admissionTestRule, "premise", "contains " + name + "(", "only evaluated, never parsed"}
	}

	cases := []admissionCase{
		{name: "field without length before the last field, bound by the hint", rules: hinted(premise(admissionCat(admissionField(term.FormatByteType, x), admissionField(term.FormatByteType, rest)))), want: unparsed("x")},
		{name: "field without length before the last field, bound by the trigger", rules: trigger(premise(admissionCat(admissionField(term.FormatByteType, x), admissionField(term.FormatByteType, rest)))), want: unparsed("x")},
		{name: "field without length before the last field, bound by another premise", rules: hinted(other(x), premise(admissionCat(admissionField(term.FormatByteType, x), admissionField(term.FormatByteType, rest)))), want: unparsed("x")},
		{name: "int field without length before the last field", rules: trigger(premise(admissionCat(admissionField(term.FormatIntType, y), admissionField(term.FormatByteType, rest))))},
		{name: "length bound by an earlier field", rules: trigger(premise(admissionCat(admissionField(term.FormatIntType, l, term.NewConstant[int64](1)), admissionField(term.FormatByteType, x, l))))},
		{name: "length bound by the trigger", rules: trigger(premise(admissionCat(admissionField(term.FormatByteType, y, x)))), want: unparsed("x")},
		{name: "bijection of a variable that another argument binds", rules: trigger(premise(y, admissionFunction(term.NotFunctionName, y))), want: unparsed("y")},
		{name: "bijection of a variable that nothing else binds", rules: trigger(premise(admissionFunction(term.ReverseFuncName, y))), want: unparsed("y")},
	}
	for _, name := range []string{term.AddFunctionName, term.AndFunctionName, term.OrFunctionName, term.XorFunctionName} {
		cases = append(cases, admissionCase{
			name:  name,
			rules: trigger(premise(y, admissionFunction(admissionTestOther, admissionFunction(name, y, term.NewConstant[int64](1))))),
			want:  constructionOnly(name),
		})
	}
	runAdmissionCases(t, cases)
}

// TestNewMonitorChecksGeneratedRules checks that the rules that the
// translation generates are admitted, and that an unbound variable of a
// source rule is found in its generated rules.
func TestNewMonitorChecksGeneratedRules(t *testing.T) {
	t.Parallel()

	k1 := term.NewVariable("k1")
	k2 := term.NewVariable("k2")
	free := term.NewVariable("free")
	h := func(arg term.Term) term.Term { return admissionFunction(admissionTestCall, arg) }
	source := func(rhs ...term.Term) *rule.Rule {
		return &rule.Rule{
			Name:  admissionTestRule,
			LHS:   []*rule.Fact{linearFact(admissionTestPremise, k1, k2)},
			RHS:   []*rule.Fact{linearFact(admissionTestResult, rhs...)},
			Attrs: map[string]rule.Attribute{},
		}
	}
	runAdmissionCases(t, []admissionCase{
		{name: "computations of premise variables", rules: rule.Translate(source(admissionFunction(admissionTestOther, h(k1), h(k2))))},
		// A call observed in a trigger or hint binds its arguments.
		{name: "variable of an observed call", rules: rule.Translate(source(admissionFunction(admissionTestOther, h(k1), h(free))))},
		{
			name:  "unbound variable",
			rules: rule.Translate(source(admissionFunction(admissionTestOther, h(k1), h(k2)), free)),
			want:  []string{"variable free of its conclusions", "cannot be bound by matching"},
		},
	})
}
