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
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessRulesDropsFactsUnusedBySelectedRules(t *testing.T) {
	specPath := filepath.Join(t.TempDir(), "roles.spthy")
	spec := `theory Roles
begin

rule Client [role="client"]:
  [ ClientState(m) ] --> [ DeadOutput(len(hash(m))), ServerState(m) ]

rule Server [role="server"]:
  [ ServerState(m) ] --> [ ServerState(m) ]

end
`
	if err := os.WriteFile(specPath, []byte(spec), 0o600); err != nil {
		t.Fatalf("write test specification: %v", err)
	}

	_, selected, _, err := ProcessRules(specPath, "client", false, nil)
	if err != nil {
		t.Fatalf("ProcessRules: %v", err)
	}
	if len(selected) != 1 || fmt.Sprint(selected[0].RHS) != "[Compute_(len(hash(m)))]" {
		t.Fatalf("selected rules = %v", selected)
	}
}
