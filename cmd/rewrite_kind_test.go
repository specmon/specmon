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
	"errors"
	"testing"

	"github.com/specmon/specmon/monitor"
)

func TestRewriteRejectsOutputsOfDifferentKinds(t *testing.T) {
	rules := `rule A [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<same(x), <>>) ]-> []
rule B [trigger=[<ba(x, y), <>>]]: [] --[ PPEvent(<same('a'), <>>) ]-> []`
	got, err := runRewriteTest(t, rules, rewriteTestEventLine(t, "ba", rewriteTestEmpty, 0x61, 2))
	t.Logf("rewritten=%q err=%v", got, err)
	if !errors.Is(err, monitor.ErrNondeterministicRewrite) {
		t.Fatalf("got %q, %v; want ErrNondeterministicRewrite", got, err)
	}
}
