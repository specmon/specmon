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
	"errors"
	"strings"
	"testing"

	"github.com/specmon/specmon/rule"

	"github.com/specmon/specmon/term"
)

func TestRewriteOutputSequenceRejectsDifferentKinds(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	text, bytes := outputWith(term.NewConstant("a")), outputWith(term.NewConstant([]byte("a")))
	_, err := rewriteOutputSequence(eventTerm("identityInput", unit), []RuleApplication{
		{actions: emitEvents(text)}, {actions: emitEvents(bytes)},
	})
	if !errors.Is(err, ErrNondeterministicRewrite) {
		t.Fatalf("got %v; want ErrNondeterministicRewrite", err)
	}
}

func TestRewriteEventHeadPolicy(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	for _, name := range []string{"slice", "reverse", "cat", "byte", "int", "string", "add", "and", "or", "xor", "not"} {
		for _, kind := range []string{"trigger", "hint", "epsilon"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				output := term.NewFunction(term.PairFunctionName, []term.Term{term.NewFunction(name, []term.Term{term.NewConstant([]byte{1, 2})}), unit})
				r := triggerRule("OuterHead", nil, nil, emitEvents(output), eventTerm("raw", unit))
				if kind != "trigger" {
					delete(r.Attrs, rule.TriggerAttributeName)
				}
				if kind == "hint" {
					r.LHS = []*rule.Fact{rule.NewFact("Seed", nil, rule.LinearFact)}
					r.Attrs[rule.HintAttributeName] = rule.TermAttribute{Value: []term.Term{eventTerm("raw", unit)}}
				}
				if _, err := NewMonitor([]*rule.Rule{r}); err == nil || !strings.Contains(err.Error(), "cannot name a rewritten event") {
					t.Fatalf("NewMonitor = %v, want forbidden-head error", err)
				}
			})
		}
	}
}

func TestRewriteOutputRejectsBoundInvalidHeads(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	for _, head := range []term.Term{term.NewConstant("bytes"), term.NewFunction("byte", []term.Term{term.NewConstant([]byte{1, 2})})} {
		output := term.NewFunction(term.PairFunctionName, []term.Term{head, unit})
		// Extraction also covers an already substituted PPEvent(e) action.
		if _, err := rewriteOutputSequence(eventTerm("raw", unit), []RuleApplication{{actions: emitEvents(output)}}); err == nil {
			t.Fatalf("accepted invalid output %s", output)
		}
		main, err := NewMonitor(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := advanceMainConfigs(main, []*Config{NewConfig()}, []*term.Function{output}, 0); err == nil {
			t.Fatalf("integrated output accepted %s", output)
		}
	}
}
