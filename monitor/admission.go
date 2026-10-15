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
	"fmt"
	"maps"
	"slices"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// checkRuleAdmission checks the static conditions under which applying r
// to a configuration is well defined: restrictions have two operands, a
// rewrite output is a pair, evaluable functions have their arity, the
// premises can be parsed on their own, and every variable that the
// application needs is bound by matching.
func checkRuleAdmission(r *rule.Rule) error {
	for _, check := range []func(*rule.Rule) error{
		checkActions, checkFunctionArity, checkPremiseParsing, checkVariableBinding,
	} {
		if err := check(r); err != nil {
			return err
		}
	}
	return nil
}

// forbiddenPremiseFunctions is the monitor's policy for calls disallowed
// in premise patterns, even when their operands are ground.
var forbiddenPremiseFunctions = map[string]bool{
	term.AddFunctionName: true,
	term.AndFunctionName: true,
	term.OrFunctionName:  true,
	term.XorFunctionName: true,
}

// checkPremiseParsing requires that every premise of r can be matched
// against a fact without values from the trigger or hint. So a premise
// contains no forbidden function and no variable at a position
// that parsing cannot extract (patternVariables), even one that another
// premise binds: the premises are matched in an order that depends on
// the facts, and the arguments of a premise are evaluated before any of
// them binds.
func checkPremiseParsing(r *rule.Rule) error {
	for _, f := range r.LHS {
		for _, arg := range f.Args {
			if call := forbiddenPremiseCall(arg); call != nil {
				return fmt.Errorf("rule %s: premise %s contains %s, which is only evaluated, never parsed", r.Name, f, call)
			}
			if needed := patternVariables(arg, nil, nil); len(needed) > 0 {
				return fmt.Errorf("rule %s: variable %s of premise %s cannot be parsed from a fact (inside an evaluated "+
					"function, in a field length or in a byte or string field without length before the last field of "+
					"a cat)", r.Name, needed[0], f)
			}
		}
	}
	return nil
}

// forbiddenPremiseCall returns the first forbidden premise call in t.
func forbiddenPremiseCall(t term.Term) *term.Function {
	fn, ok := t.(*term.Function)
	if !ok {
		return nil
	}
	if forbiddenPremiseFunctions[fn.Name] {
		return fn
	}
	for _, arg := range fn.Args {
		if call := forbiddenPremiseCall(arg); call != nil {
			return call
		}
	}
	return nil
}

// premiseBindings returns the variables that matching the premises of r
// against the facts binds.
func premiseBindings(r *rule.Rule) map[string]bool {
	bound := make(map[string]bool)
	for _, f := range r.LHS {
		for _, arg := range f.Args {
			patternVariables(arg, nil, bound)
		}
	}
	return bound
}

// checkActions requires that a restriction has two operands and that a
// rewrite action emits a pair of an event and its result.
func checkActions(r *rule.Rule) error {
	for _, action := range r.Act {
		switch action.Name {
		case restrictionEq, restrictionEqual, restrictionNeq, restrictionNotEqual, restrictionUnequal:
			if len(action.Args) != 2 {
				return fmt.Errorf("rule %s: restriction %s has %d operands, want two", r.Name, action, len(action.Args))
			}
		case rule.RewriteEventName:
			if len(action.Args) != 1 {
				return fmt.Errorf("rule %s: action %s has %d arguments, want one", r.Name, action, len(action.Args))
			}
			event, result := term.SplitPair(action.RewriteTerm())
			if event == nil || result == nil {
				return fmt.Errorf("rule %s: action %s does not emit a pair <event, result>", r.Name, action)
			}
			if fn, ok := event.(*term.Function); ok && fn != nil && forbiddenRewriteHead(fn.Name) {
				return fmt.Errorf("rule %s: built-in %s cannot name a rewritten event", r.Name, fn.Name)
			}
		}
	}
	return nil
}

// checkFunctionArity checks the number of arguments of the evaluable
// functions in r and of the format fields of every cat.
func checkFunctionArity(r *rule.Rule) error {
	for _, t := range ruleTerms(r) {
		if err := checkTermArity(t); err != nil {
			return fmt.Errorf("rule %s: %w", r.Name, err)
		}
	}
	return nil
}

func checkTermArity(t term.Term) error {
	fn, ok := t.(*term.Function)
	if !ok {
		return nil
	}
	if want, ok := term.BuiltinArity(fn.Name); ok && len(fn.Args) != want {
		return fmt.Errorf("%s has %d arguments, want %d", fn, len(fn.Args), want)
	}
	if fn.Name == term.CatFunctionName {
		for _, arg := range fn.Args {
			if !isFormatField(arg) {
				return fmt.Errorf("argument %s of %s is not an int, byte or string field with one or two arguments", arg, fn)
			}
		}
	}
	for _, arg := range fn.Args {
		if err := checkTermArity(arg); err != nil {
			return err
		}
	}
	return nil
}

func isFormatField(t term.Term) bool {
	field, ok := t.(*term.Function)
	if !ok {
		return false
	}
	switch term.FormatType(field.Name) {
	case term.FormatIntType, term.FormatByteType, term.FormatStringType:
		return len(field.Args) == 1 || len(field.Args) == 2
	}
	return false
}

// ruleTerms returns the arguments of every fact of r and its triggers and
// hints.
func ruleTerms(r *rule.Rule) []term.Term {
	var terms []term.Term
	for _, f := range slices.Concat(r.LHS, r.Act, r.RHS) {
		terms = append(terms, f.Args...)
	}
	return slices.Concat(terms, r.Triggers(), r.Hints())
}

// checkVariableBinding requires that every variable of the premises,
// actions and conclusions of r is bound whenever r is selected: it must
// occur in a premise or in the trigger or hint that matched the event.
// Whenever these patterns match, all their variables are bound, so the
// application is ground. A hint is an alternative of the other hints of
// its rule, so each hint must provide on its own what the premises leave
// open. A rule with several triggers applies its conclusions once all have
// arrived.
//
// Whether the patterns can match at all is a separate question, which
// unmatchableVariables answers with warnings.
func checkVariableBinding(r *rule.Rule) error {
	check := func(when string, patterns ...term.Term) error {
		occurring := make(map[string]bool)
		for _, v := range slices.Concat(rule.Facts(r.LHS).Vars(), term.Terms(patterns).Vars()) {
			occurring[v.Name] = true
		}
		for i, facts := range [][]*rule.Fact{r.Act, r.RHS} {
			for _, v := range rule.Facts(facts).Vars() {
				if !occurring[v.Name] {
					return fmt.Errorf("rule %s: variable %s of its %s cannot be bound by matching%s",
						r.Name, v.Name, [...]string{"actions", "conclusions"}[i], when)
				}
			}
		}
		return nil
	}
	if triggers := r.Triggers(); len(triggers) > 0 || !r.HasHints() {
		if err := check("", triggers...); err != nil {
			return err
		}
	}
	for _, hint := range r.Hints() {
		if err := check(fmt.Sprintf(" when hint %s matches", hint), hint); err != nil {
			return err
		}
	}
	return nil
}

// Warnings returns what loading finds about rules without rejecting them:
// patterns that match only terms that contain an evaluable subterm
// unevaluated, because a variable is not bound in time.
func Warnings(rules []*rule.Rule) []string {
	var warnings []string
	for _, r := range rules {
		warnings = append(warnings, unmatchableVariables(r)...)
	}
	return warnings
}

// unmatchableVariables returns a message for every variable that a trigger
// or hint of r needs at a position that matching cannot parse
// (patternVariables) and that is not bound when the pattern is matched.
// Such a pattern matches only a term that contains the subterm
// unevaluated. It does not make an application non-ground, so it is a
// warning, not a rejection. A trigger or hint is matched with the bindings
// of the premises. A later trigger of a rule with several triggers also
// with those of the triggers that arrived before it. The premises are
// parsed on their own (checkPremiseParsing).
func unmatchableVariables(r *rule.Rule) []string {
	premises := premiseBindings(r)
	var messages []string
	reported := make(map[string]bool)
	report := func(v, when string) {
		if reported[v+when] {
			return
		}
		reported[v+when] = true
		messages = append(messages, fmt.Sprintf("rule %s: variable %s is not bound when matching needs its value "+
			"(inside an evaluated function, in a field length or in a byte or string field without length before the "+
			"last field of a cat), so the pattern matches only terms that contain such a subterm unevaluated%s",
			r.Name, v, when))
	}

	triggers := r.Triggers()
	for i, trigger := range triggers {
		others := maps.Clone(premises)
		for _, other := range slices.Concat(triggers[:i], triggers[i+1:]) {
			patternVariables(other, nil, others)
		}
		for _, v := range patternVariables(trigger, premises, nil) {
			when := ""
			if others[v] {
				when = fmt.Sprintf(" when trigger %s arrives first", trigger)
			}
			report(v, when)
		}
	}
	for _, hint := range r.Hints() {
		for _, v := range patternVariables(hint, premises, nil) {
			report(v, fmt.Sprintf(" when hint %s matches", hint))
		}
	}
	return messages
}

// patternVariables walks t as matching it against a ground term does. It
// adds to binds, if not nil, the variables that matching binds, and it
// returns, in the order in which they occur, the variables that matching
// needs to know and that are not in bound. Below an evaluable function
// other than cat, which matching evaluates instead of parsing, a variable
// is needed: it could bind there only against a term that contains the
// subterm unevaluated. A cat is parsed field by field: the value of a
// field binds, and a length is needed unless an earlier field of the same
// cat binds it. The value of an open field (openField) is needed.
func patternVariables(t term.Term, bound, binds map[string]bool) []string {
	var needed []string
	seen := make(map[string]bool)
	need := func(u term.Term, local map[string]bool) {
		for _, v := range term.Vars(u) {
			if !bound[v.Name] && !local[v.Name] && !seen[v.Name] {
				seen[v.Name] = true
				needed = append(needed, v.Name)
			}
		}
	}
	var walk func(t term.Term)
	walk = func(t term.Term) {
		switch fn := t.(type) {
		case *term.Variable:
			if binds != nil {
				binds[fn.Name] = true
			}
		case *term.Function:
			switch {
			case fn.Name == term.CatFunctionName:
				parsed := make(map[string]bool)
				last := len(fn.Args) - 1
				for i, arg := range fn.Args {
					field, ok := arg.(*term.Function)
					if !ok || len(field.Args) == 0 {
						continue
					}
					if len(field.Args) > 1 {
						need(field.Args[1], parsed)
					}
					if value, ok := field.Args[0].(*term.Variable); ok && !openField(field, i, last) {
						parsed[value.Name] = true
						continue
					}
					need(field.Args[0], parsed)
				}
				if binds != nil {
					maps.Copy(binds, parsed)
				}
			case fn.MayEvalToConstant():
				need(fn, nil)
			default:
				for _, arg := range fn.Args {
					walk(arg)
				}
			}
		}
	}
	walk(t)
	return needed
}

// openField reports whether field, the i-th of a cat whose last field has
// the index last, is a byte or string field without length that is not
// the last field. Parsing cannot tell where such a field ends, so its
// value must be known. An int field without length takes eight bytes.
func openField(field *term.Function, i, last int) bool {
	return len(field.Args) == 1 && i < last && term.FormatType(field.Name) != term.FormatIntType
}
