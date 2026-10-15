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

package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
)

// A parsed rewrite model whose two rules emit outputs that differ only in
// constant kind: x is the bytes constant 0x61 from the trace, 'a' a string.
func TestMonitorReportsRewriteOutputsOfDifferentKinds(t *testing.T) {
	rewritePath := writeMonitorSpec(t, `rule A [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<same(x), <>>) ]-> []
rule B [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<same('a'), <>>) ]-> []`)
	mainPath := writeMonitorSpec(t, `rule Same [trigger=[<same(v), <>>]]: [] --> []`)
	input, err := json.Marshal(&monitor.TimedEvent{Event: term.NewFunction(term.PairFunctionName, []term.Term{
		term.NewFunction("ba", []term.Term{term.NewConstant([]byte("a")), term.NewConstant([]byte{2})}),
		term.NewFunction(term.PairFunctionName, nil),
	})})
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	config := MonitorConfig{In: writeMonitorInput(t, append(input, '\n')), RewriteWith: rewritePath}
	cmd := monitorTestCommand()
	if err := config.RunE(cmd, []string{mainPath}); err != nil {
		t.Fatalf("RunE: %v", err)
	}
	output := cmd.OutOrStdout().(*bytes.Buffer).String()
	t.Logf("output:\n%s", output)
	if !strings.Contains(output, "<same(0x61), <>>") || !strings.Contains(output, "<same('a'), <>>") {
		t.Fatalf("consumed events do not list both outputs")
	}
}
