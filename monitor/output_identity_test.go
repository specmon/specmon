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
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

func outputWith(value term.Term) *term.Function {
	return term.NewFunction(term.PairFunctionName, []term.Term{
		term.NewFunction("identityOutput", []term.Term{value}),
		term.NewFunction(term.PairFunctionName, nil),
	})
}

func TestPipelineReportsOutputsOfDifferentKinds(t *testing.T) {
	unit := term.NewFunction(term.PairFunctionName, nil)
	input := eventTerm("identityInput", unit)
	text, bytes := outputWith(term.NewConstant("a")), outputWith(term.NewConstant([]byte("a")))
	_, _, consumed, violation, err := runTestPipeline(t, []*rule.Rule{
		triggerRule("IdentityText", nil, nil, emitEvents(text), input),
		triggerRule("IdentityBytes", nil, nil, emitEvents(bytes), input),
	}, []*rule.Rule{triggerRule("IdentityAccept", nil, nil, nil, outputWith(term.NewVariable("value")))}, input)
	if violation != nil || err != nil {
		t.Fatalf("pipeline=(%v,%v)", violation, err)
	}
	if len(consumed) != 2 {
		t.Fatalf("reported %v; want both differently typed outputs", consumed)
	}
}
