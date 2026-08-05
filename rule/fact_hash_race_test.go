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

package rule_test

import (
	"sync"
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// TestFactHashConcurrentAccess pins the no-race property of Fact.Hash:
// many goroutines hashing the SAME *Fact pointer concurrently must
// complete cleanly under the race detector and produce a single
// consistent value. The earlier non-atomic cache fired data races
// under exactly this access pattern (the parallel subtests in
// term/term_test.go).
//
// Run with -race to make this test load-bearing.
func TestFactHashConcurrentAccess(t *testing.T) {
	f := rule.NewFact("F", []term.Term{
		term.NewConstant("a"),
		term.NewVariable("x"),
		term.NewFunction("pair", []term.Term{
			term.NewConstant("b"),
			term.NewConstant("c"),
		}),
	}, rule.LinearFact)

	const goroutines = 32
	const iterations = 1000

	var wg sync.WaitGroup
	var mu sync.Mutex
	var hashes []uint64

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last uint64
			for i := 0; i < iterations; i++ {
				h := f.Hash()
				if h == 0 {
					t.Errorf("Hash() returned 0; sentinel-collision path?")
					return
				}
				if last != 0 && h != last {
					t.Errorf("Hash() returned %d then %d for same Fact", last, h)
					return
				}
				last = h
			}
			mu.Lock()
			hashes = append(hashes, last)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(hashes) != goroutines {
		t.Fatalf("expected %d hashes, got %d", goroutines, len(hashes))
	}
	first := hashes[0]
	for i, h := range hashes {
		if h != first {
			t.Errorf("goroutine %d saw hash %d, want %d", i, h, first)
		}
	}
}
