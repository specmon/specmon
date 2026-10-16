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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/term"
)

// rewriteOutputTestRules keep or wrap the calls of their triggers in the
// rewritten events.
const rewriteOutputTestRules = `rule Unary [trigger=[<ua(x), <>>]]: [] --[ PPEvent(<ua(x), <>>), PPEvent(<ua(x), ua(x)>) ]-> []
rule Binary [trigger=[<ba(x, z), <>>]]: [] --[ PPEvent(<ba(x, z), <>>) ]-> []
rule Nested [trigger=[<uz(x), r>]]:
  [] --[ Eq(uz(x), r), PPEvent(<wrapped(uz(x)), <>>), PPEvent(<uz(x), uz(x)>) ]-> [ Stored(uz(x)) ]
rule Stored [trigger=[<stored(v), <>>]]: [ Stored(v) ] --[ PPEvent(<stored(v), <>>) ]-> []
rule Call [trigger=[<enter(t, x), <>>, <leave(t, x), y>]]:
  [] --[ PPEvent(<enter(t, x), leave(t, x)>), PPEvent(<leave(t, x), <>>) ]-> []
`

var rewriteTestEmpty = term.NewFunction(term.PairFunctionName, nil)

// rewriteTestEventLine returns a trace line with the event
// <name(args), result>, whose arguments are one-byte constants.
func rewriteTestEventLine(t *testing.T, name string, result term.Term, args ...byte) string {
	t.Helper()
	terms := make([]term.Term, len(args))
	for i, arg := range args {
		terms[i] = term.NewConstant([]byte{arg})
	}
	event := &monitor.TimedEvent{Event: term.NewFunction(term.PairFunctionName, []term.Term{
		term.NewFunction(name, terms),
		result,
	})}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return string(encoded) + "\n"
}

// rewriteOutputTestWant lists the rewritten events. The outer call of each
// PPEvent is kept. Nested calls, the result, other actions and conclusions
// denote the observed results.
var rewriteOutputTestWant = []string{
	"<ua(0x01), <>>",
	"<ua(0x01), <>>",
	"<ba(0x04, 0x05), <>>",
	"<wrapped(0x09), <>>",
	"<uz(0x08), 0x09>",
	"<stored(0x09), <>>",
	"<enter(0x01, 0x02), 0x03>",
	"<leave(0x01, 0x02), <>>",
}

// runRewriteTest runs the rewrite command and returns the rewritten events.
func runRewriteTest(t *testing.T, rules, input string) ([]string, error) {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), "out.jsonl")
	config := RewriteConfig{
		JSON: true,
		In:   writeMonitorInput(t, []byte(input)),
		Out:  outPath,
	}
	runErr := config.RunE(monitorTestCommand(), []string{writeMonitorSpec(t, rules)})

	output, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var events []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		var event monitor.TimedEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		events = append(events, event.Event.String())
	}
	return events, runErr
}

func TestRewriteKeepsOutputCall(t *testing.T) {
	input := rewriteTestEventLine(t, "ua", rewriteTestEmpty, 1) +
		rewriteTestEventLine(t, "ba", rewriteTestEmpty, 4, 5) +
		rewriteTestEventLine(t, "uz", term.NewConstant([]byte{9}), 8) +
		rewriteTestEventLine(t, "stored", rewriteTestEmpty, 9) +
		rewriteTestEventLine(t, "enter", rewriteTestEmpty, 1, 2) +
		rewriteTestEventLine(t, "leave", term.NewConstant([]byte{3}), 1, 2)
	got, err := runRewriteTest(t, rewriteOutputTestRules, input)
	if err != nil {
		t.Fatalf("RunE: %v", err)
	}
	if strings.Join(got, "\n") != strings.Join(rewriteOutputTestWant, "\n") {
		t.Fatalf("rewritten events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(rewriteOutputTestWant, "\n"))
	}
}

func TestMacroAnnotationMatching(t *testing.T) {
	const macros = "macros: packet(x) = cat(byte(x, '1'))\n"
	const trigger = "<recv(packet(x)), packet(y)>"
	for _, hinted := range []bool{false, true} {
		rules := macros + "rule Receive [trigger=[" + trigger + "]]: [] --[ PPEvent(<parsed(x), y>) ]-> []"
		prefix := ""
		if hinted {
			rules = macros + "rule Setup [trigger=[<setup(), <>>]]: [] --> [ Ready() ]\n" +
				"rule Start [hint=[" + trigger + "]]: [ Ready() ] --> [ Pending(x, y) ]\n" +
				"rule Receive [trigger=[" + trigger + "]]: [ Pending(x, y) ] --[ PPEvent(<parsed(x), y>) ]-> []"
			prefix = rewriteTestEventLine(t, "setup", rewriteTestEmpty)
		}
		input := prefix + rewriteTestEventLine(t, "recv", term.NewConstant([]byte{2}), 1)
		t.Run(fmt.Sprintf("hint=%t", hinted), func(t *testing.T) {
			t.Run("rewrite", func(t *testing.T) {
				got, err := runRewriteTest(t, rules, input)
				if err != nil || strings.Join(got, "\n") != "<parsed(0x01), 0x02>" {
					t.Fatalf("rewrite = %v, %v; want <parsed(0x01), 0x02>", got, err)
				}
			})
			t.Run("short result", func(t *testing.T) {
				got, err := runRewriteTest(t, rules, prefix+rewriteTestEventLine(t, "recv", term.NewConstant([]byte{}), 1))
				if len(got) != 0 || !errors.Is(err, monitor.ErrNoApplicableRule) {
					t.Fatalf("rewrite = %v, %v; want a rejected event without output", got, err)
				}
			})
			for _, integrated := range []bool{false, true} {
				t.Run(fmt.Sprintf("monitor integrated=%t", integrated), func(t *testing.T) {
					path := writeMonitorSpec(t, rules)
					config := MonitorConfig{In: writeMonitorInput(t, []byte(input))}
					if integrated {
						config.RewriteWith = path
						path = writeMonitorSpec(t, macros+"rule Consume [trigger=[<parsed(packet(x)), packet(y)>]]: [] --> []")
					}
					command := monitorTestCommand()
					if err := config.RunE(command, []string{path}); err != nil {
						t.Fatalf("monitor: %v", err)
					}
					want := "1: <recv(0x01), 0x02>"
					if hinted {
						want = "2: <recv(0x01), 0x02>"
					}
					if integrated {
						want = "1: <parsed(0x01), 0x02>"
					}
					if got := command.OutOrStdout().(*bytes.Buffer).String(); !strings.Contains(got, want) {
						t.Fatalf("monitor output = %s, want %s", got, want)
					}
				})
			}
		})
	}
}

func TestMonitorConsumesKeptRewriteOutputCall(t *testing.T) {
	rewritePath := writeMonitorSpec(t, `rule Unary [trigger=[<ua(x), <>>]]: [] --[ PPEvent(<ua(x), <>>) ]-> []
rule Binary [trigger=[<ba(x, z), <>>]]: [] --[ PPEvent(<ba(x, z), <>>) ]-> []`)
	mainPath := writeMonitorSpec(t, `rule Unary [trigger=[<ua(x), <>>]]: [] --> [ Seen(x) ]
rule Binary [trigger=[<ba(x, z), <>>]]: [ Seen(x) ] --> []`)

	input := rewriteTestEventLine(t, "ua", rewriteTestEmpty, 1) + rewriteTestEventLine(t, "ba", rewriteTestEmpty, 1, 5)
	config := MonitorConfig{In: writeMonitorInput(t, []byte(input)), RewriteWith: rewritePath}
	cmd := monitorTestCommand()
	if err := config.RunE(cmd, []string{mainPath}); err != nil {
		t.Fatalf("RunE: %v", err)
	}
	output := cmd.OutOrStdout().(*bytes.Buffer).String()
	if !strings.Contains(output, "1: <ua(0x01), <>>") || !strings.Contains(output, "2: <ba(0x01, 0x05), <>>") {
		t.Fatalf("consumed events:\n%s", output)
	}
}

func TestRewriteRequiresDeterministicRules(t *testing.T) {
	input := rewriteTestEventLine(t, "ba", rewriteTestEmpty, 1, 2) + rewriteTestEventLine(t, "ua", rewriteTestEmpty, 3)
	const next = "\nrule Next [trigger=[<ua(x), <>>]]: [] --[ PPEvent(<next(x), <>>) ]-> []"

	for _, test := range []struct {
		name      string
		rules     string
		want      []string
		wantErr   error
		wantParts []string
	}{
		{
			name:  "one rule",
			rules: `rule Pair [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<first(x), <>>), PPEvent(<second(y), <>>) ]-> []`,
			want:  []string{"<first(0x01), <>>", "<second(0x02), <>>", "<next(0x03), <>>"},
		},
		{
			name: "identical outputs",
			rules: `rule A [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<same(x), <>>) ]-> [ A() ]
rule B [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<same(x), <>>) ]-> [ B() ]`,
			want: []string{"<same(0x01), <>>", "<next(0x03), <>>"},
		},
		{
			name: "different outputs",
			rules: `rule Good [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<goodev(x, y), <>>) ]-> []
rule Bad [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<badev(x, y), <>>) ]-> []`,
			wantErr:   monitor.ErrNondeterministicRewrite,
			wantParts: []string{"the rule applications for <ba(0x01, 0x02), <>>", "2 different event sequences", "specmon monitor -R"},
		},
		{
			name: "output and no output",
			rules: `rule Emit [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<goodev(x, y), <>>) ]-> []
rule Ignore [trigger=[<ba(x, y), <>>]]: [] --> []`,
			wantErr:   monitor.ErrNondeterministicRewrite,
			wantParts: []string{"<ba(0x01, 0x02), <>>", "2 different event sequences"},
		},
		{
			name:      "unmatched event",
			rules:     `rule Other [trigger=[<other(x, y), <>>]]: [] --[ PPEvent(<goodev(x, y), <>>) ]-> []`,
			wantErr:   monitor.ErrNoApplicableRule,
			wantParts: []string{"rewrite violation"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := runRewriteTest(t, test.rules+next, input)
			if test.wantErr == nil {
				if err != nil || strings.Join(got, "\n") != strings.Join(test.want, "\n") {
					t.Fatalf("rewritten events = %q, %v; want %q", got, err, test.want)
				}
				return
			}
			if !errors.Is(err, test.wantErr) || len(got) != 0 {
				t.Fatalf("RunE = %q, %v; want no events and %v", got, err, test.wantErr)
			}
			for _, part := range test.wantParts {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("error %q does not contain %q", err, part)
				}
			}
		})
	}
}

func TestRewriteBoundHeadsAndNestedBuiltins(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		head         term.Term
		want         string
		invalid      bool
	}{
		{"bytes", "<e, r>", term.NewConstant([]byte{1, 2}), "", true},
		{"reverse", "<e, r>", term.NewFunction("reverse", []term.Term{term.NewConstant([]byte{1, 2})}), "", true},
		{"byte", "<e, r>", term.NewFunction("byte", []term.Term{term.NewConstant([]byte{1, 2})}), "", true},
		{"pair", "<<e, e>, r>", term.NewConstant([]byte{1, 2}), "<<0x0102, 0x0102>, <>>", false},
		{"nested", "<receive(reverse(e)), r>", term.NewConstant([]byte{1, 2}), "<receive(0x0201), <>>", false},
	} {
		for _, kind := range []string{"trigger", "hint", "epsilon"} {
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				rules := "rule Rewrite [trigger=[<raw(e), r>]]: [] --[PPEvent(" + tc.action + ")]-> []"
				prefix := ""
				if kind == "hint" {
					rules = "rule Seed [trigger=[<seed(), <>>]]: [] --> [Seed()]\n" +
						"rule Rewrite [hint=[<raw(e), r>]]: [Seed()] --[PPEvent(" + tc.action + ")]-> [Ready()]\n" +
						"rule Finish [trigger=[<raw(e), r>]]: [Ready()] --> []"
					prefix = rewriteTestEventLine(t, "seed", rewriteTestEmpty)
				}
				if kind == "epsilon" {
					rules = "rule Start [trigger=[<raw(e), r>]]: [] --> [Ready(e,r)]\n" +
						"rule Rewrite [no-decomp]: [Ready(e,r)] --[PPEvent(" + tc.action + ")]-> []"
				}
				event := &monitor.TimedEvent{Event: term.NewFunction(term.PairFunctionName, []term.Term{term.NewFunction("raw", []term.Term{tc.head}), rewriteTestEmpty})}
				line, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				input := prefix + string(line) + "\n"
				got, err := runRewriteTest(t, rules, input)
				if tc.invalid {
					if err == nil || len(got) != 0 {
						t.Fatalf("rewrite = %v, %v; want rejection without output", got, err)
					}
				} else if err != nil || strings.Join(got, "\n") != tc.want {
					t.Fatalf("rewrite = %v, %v; want %s", got, err, tc.want)
				}
				core := "rule Main [trigger=[<receive(x), r>]]: [] --> []"
				if tc.name == "pair" {
					core = "rule Main [trigger=[<<x, y>, r>]]: [] --> []"
				}
				// The byte case would be accepted by this matching core without the
				// integrated forbidden-name check.
				if tc.name == "byte" {
					core = "rule Main [trigger=[<byte(x), r>]]: [] --> []"
				}
				config := MonitorConfig{In: writeMonitorInput(t, []byte(input)), RewriteWith: writeMonitorSpec(t, rules)}
				err = config.RunE(monitorTestCommand(), []string{writeMonitorSpec(t, core)})
				if tc.invalid != (err != nil) {
					t.Fatalf("integrated error = %v, invalid = %v", err, tc.invalid)
				}
			})
		}
	}
}

func TestInvalidBoundRewriteHeadPreservesValidSibling(t *testing.T) {
	for _, head := range []term.Term{term.NewConstant([]byte{1, 2}), term.NewFunction("byte", []term.Term{term.NewConstant([]byte{1, 2})})} {
		event := monitor.TimedEvent{Event: term.NewFunction(term.PairFunctionName, []term.Term{term.NewFunction("raw", []term.Term{head}), rewriteTestEmpty})}
		line, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		rewrite := writeMonitorSpec(t, `rule Bad [trigger=[<raw(e), r>]]: [] --[PPEvent(<e, r>)]-> []
rule Good [trigger=[<raw(e), r>]]: [] --[PPEvent(<valid(), r>)]-> []`)
		core := writeMonitorSpec(t, `rule Main [trigger=[<valid(), r>]]: [] --> []`)
		config := MonitorConfig{In: writeMonitorInput(t, append(line, '\n')), RewriteWith: rewrite}
		command := monitorTestCommand()
		if err := config.RunE(command, []string{core}); err != nil {
			t.Fatalf("valid sibling rejected for %s: %v", head, err)
		}
		output := command.OutOrStdout().(*bytes.Buffer).String()
		if !strings.Contains(output, "1: <valid(), <>>") || strings.Contains(output, "2:") {
			t.Fatalf("consumed output = %s", output)
		}
	}
}
