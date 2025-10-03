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

package monitor_test

import (
	"github.com/specmon/specmon/cmd"
	"testing"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// TestMonitorMultipleFrFacts tests a bug in conflictSet with a
// rule with two Fr facts, and we test the internal rule matching logic.
func TestMonitorMultipleFrFacts(t *testing.T) {
	// Create a simple rule that consumes two Fr facts with a pseudo trigger
	testRule := &rule.Rule{
		Name: "TwoFr",
		LHS: []*rule.Fact{
			rule.NewFact("Fr", []term.Term{term.NewVariable("x")}, rule.LinearFact),
			rule.NewFact("Fr", []term.Term{term.NewVariable("y")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("x"), term.NewVariable("y")}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("test", []term.Term{}),
						term.NewFunction("pair", []term.Term{}),
					}),
				},
			},
		},
	}

	// Retrieve User Settings
	// factArgMaxLen specifies the maximum length of a fact's arguments before they are truncated in log output.
	logArgTruncate, err := cmd.Root().Flags().GetInt64("log-arg-truncate")

	// Define User Settings for Monitor
	settings := make(map[string]interface{})
	settings["logArgTruncate"] = logArgTruncate

	// Create monitor with this rule
	mon, err := monitor.NewMonitor([]*rule.Rule{testRule}, settings)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	// Get the initial config and add two Fr facts with different values
	configs := mon.Configs()
	if len(configs) != 1 {
		t.Fatalf("Expected 1 initial config, got %d", len(configs))
	}
	config := configs[0]

	// Add two Fr facts with different values
	// The conflictSet bug should affect how these are matched by the rule
	config.AddFact(rule.NewFact("Fr", []term.Term{term.NewConstant("alice")}, rule.LinearFact))
	config.AddFact(rule.NewFact("Fr", []term.Term{term.NewConstant("bob")}, rule.LinearFact))

	// Verify we have 2 facts
	if len(config.Facts()) != 2 {
		t.Fatalf("Expected 2 facts, got %d", len(config.Facts()))
	}

	// Process the test event that matches our pseudo trigger
	testEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("test", []term.Term{}),
		term.NewFunction("pair", []term.Term{}),
	})

	err = mon.ProcessEvent(testEvent)
	if err != nil {
		t.Fatalf("ProcessEvent failed: %v", err)
	}

	// Check the resulting configurations
	// The broken conflictSet should cause different behavior in rule matching
	resultConfigs := mon.Configs()
	if len(resultConfigs) == 0 {
		t.Errorf("Expected some configurations after processing event")
	}

	t.Logf("Processed event successfully, got %d result configs", len(resultConfigs))
}
