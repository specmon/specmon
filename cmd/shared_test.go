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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/specmon/specmon/rule"
)

func TestProcessRulesFiltersBeforeDroppingAndDecomposing(t *testing.T) {
	specPath := filepath.Join(t.TempDir(), "roles.spthy")
	spec := `theory Roles
begin

rule Client [role="client"]:
  [ ClientState(m) ]
  -->
  [ DeadOutput(len(hash(m))), ServerState(m) ]

rule Server [role="server"]:
  [ ServerState(m) ]
  -->
  [ ServerState(m) ]

end
`
	if err := os.WriteFile(specPath, []byte(spec), 0o600); err != nil {
		t.Fatalf("write test specification: %v", err)
	}

	for _, decompose := range []bool{false, true} {
		name := "without_decomposition"
		if decompose {
			name = "with_decomposition"
		}
		t.Run(name, func(t *testing.T) {
			original, selected, processed, err := ProcessRules(specPath, "client", decompose, nil)
			if err != nil {
				t.Fatalf("ProcessRules: %v", err)
			}
			if len(original) != 2 || len(original[0].RHS) != 2 || len(original[0].Act) != 0 {
				t.Fatalf("parsed rules changed during processing: %#v", original)
			}
			if len(selected) != 1 || selected[0].Name != "Client" {
				t.Fatalf("role filtering selected unexpected rules: %#v", selected)
			}
			if len(selected[0].RHS) != 1 || selected[0].RHS[0].Name != rule.ComputeFactName {
				t.Fatalf("selected rule has unexpected RHS: %#v", selected[0].RHS)
			}
			if len(selected[0].Act) != 0 {
				t.Fatalf("processing introduced public actions: %#v", selected[0].Act)
			}

			for _, processedRule := range processed {
				for _, fact := range processedRule.RHS {
					if fact.Name == "DeadOutput" || fact.Name == "ServerState" {
						t.Fatalf("dead RHS fact survived processing: %s", fact)
					}
				}
				for _, action := range processedRule.Act {
					if action.Name == rule.ComputeFactName {
						t.Fatalf("internal computation became an action: %s", action)
					}
				}
			}

			if !decompose {
				if len(processed) != 1 || len(processed[0].RHS) != 1 ||
					processed[0].RHS[0].Name != rule.ComputeFactName ||
					processed[0].RHS[0].Args[0].String() != "len(hash(m))" {
					t.Fatalf("non-decomposed computation changed: %#v", processed)
				}
				return
			}

			var foundCompute, foundHashTrigger, foundLenTrigger bool
			for _, processedRule := range processed {
				for _, fact := range processedRule.RHS {
					foundCompute = foundCompute || fact.Name == rule.ComputeFactName
				}
				for _, trigger := range processedRule.Triggers() {
					foundHashTrigger = foundHashTrigger || strings.Contains(trigger.String(), "hash(")
					foundLenTrigger = foundLenTrigger || strings.Contains(trigger.String(), "len(")
				}
			}
			if !foundCompute || !foundHashTrigger || !foundLenTrigger {
				t.Fatalf("decomposition lost computation dependencies: compute=%t hash=%t len=%t",
					foundCompute, foundHashTrigger, foundLenTrigger)
			}
		})
	}
}
