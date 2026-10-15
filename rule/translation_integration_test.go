// Copyright (C) 2025-2026 CISPA Helmholtz Center for Information Security
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

package rule_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/specmon/specmon/cmd"
	"github.com/specmon/specmon/parser"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
	"github.com/stretchr/testify/require"
)

// TestTranslationFromFiles tests the rule decomposition/translation functionality
// using file-based test cases. Each test case consists of:
// - input.spthy: Original rules to be decomposed,
// - expected.spthy: Expected decomposed rules.
func TestTranslationFromFiles(t *testing.T) {
	allFiles, err := filepath.Glob("../testdata/translation/*")
	require.NoError(t, err)

	// Filter to only include directories and exclude README.md
	var testCases []string
	for _, path := range allFiles {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			// Skip any directories that might not be test cases (like .git, etc.)
			if !strings.HasPrefix(filepath.Base(path), ".") {
				testCases = append(testCases, path)
			}
		}
	}

	require.NotEmpty(t, testCases, "No test cases found in testdata/translation/")

	for _, testDir := range testCases {
		t.Run(filepath.Base(testDir), func(t *testing.T) {
			inputPath := filepath.Join(testDir, "input.spthy")
			expectedPath := filepath.Join(testDir, "expected.spthy")

			// Parse expected output
			expectedRules, err := parser.ParseFile(context.Background(), expectedPath, nil)
			require.NoError(t, err, "Failed to parse expected.spthy")

			// Run decomposition on input
			processed, err := cmd.ProcessRules(context.Background(), inputPath, "", true, nil)
			require.NoError(t, err, "Failed to process input rules")

			// Compare rules
			assertRulesEqual(t, expectedRules, processed.Executable)
			assertCarriedTuplesConsistent(t, processed.Executable)
		})
	}
}

// TestTranslateOrderIndependent verifies that reordering RHS facts in a rule
// produces identical decomposed output. This is an end-to-end regression test
// for naming stability through the full Translate pipeline.
//
// Mid-rule numbering (R_0, R_1, ...) depends on DAG traversal order and may
// differ between orderings, so we compare rule bodies after stripping the
// rule name from each string representation.
func TestTranslateOrderIndependent(t *testing.T) {
	t.Parallel()

	m := term.NewVariable("m")
	k := term.NewVariable("k")
	hashM := term.NewFunction("hash", []term.Term{m})
	hmacK := term.NewFunction("hmac", []term.Term{k})
	lenHashM := term.NewFunction("len", []term.Term{hashM})

	lhs := []*rule.Fact{
		rule.NewFact("State0", []term.Term{m, k}, rule.LinearFact),
	}

	// Order A: Out(len(hash(m))) before Out(hmac(k)).
	rA := &rule.Rule{
		Name: "R",
		LHS:  lhs,
		Act:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("Out", []term.Term{lenHashM}, rule.LinearFact),
			rule.NewFact("Out2", []term.Term{hmacK}, rule.LinearFact),
			rule.NewFact("State1", []term.Term{m, k}, rule.LinearFact),
		},
		Attrs: make(map[string]rule.Attribute),
	}

	// Order B: Out(hmac(k)) before Out(len(hash(m))).
	rB := &rule.Rule{
		Name: "R",
		LHS:  lhs,
		Act:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("Out2", []term.Term{hmacK}, rule.LinearFact),
			rule.NewFact("Out", []term.Term{lenHashM}, rule.LinearFact),
			rule.NewFact("State1", []term.Term{m, k}, rule.LinearFact),
		},
		Attrs: make(map[string]rule.Attribute),
	}

	rulesA := rule.Translate(rA)
	rulesB := rule.Translate(rB)

	require.Len(t, rulesB, len(rulesA), "Different number of decomposed rules")

	// Compare the set of rule bodies, ignoring mid-rule numbering.
	bodiesA := normalizedRuleBodies(rulesA)
	bodiesB := normalizedRuleBodies(rulesB)

	sort.Strings(bodiesA)
	sort.Strings(bodiesB)

	require.Equal(t, bodiesA, bodiesB,
		"Decomposed rule bodies differ between RHS orderings")
}

// TestTranslateDepth1OrderIndependent verifies that reordering RHS facts in a
// depth-1 rule (single-level function applications, no mid-rules) produces
// identical trigger attributes regardless of fact ordering.
func TestTranslateDepth1OrderIndependent(t *testing.T) {
	t.Parallel()

	m := term.NewVariable("m")
	k := term.NewVariable("k")
	hashM := term.NewFunction("hash", []term.Term{m})
	hmacK := term.NewFunction("hmac", []term.Term{k})

	lhs := []*rule.Fact{
		rule.NewFact("State0", []term.Term{m, k}, rule.LinearFact),
	}

	// Order A: Out(hash(m)) before Out(hmac(k)).
	rA := &rule.Rule{
		Name: "R",
		LHS:  lhs,
		Act:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("Out", []term.Term{hashM}, rule.LinearFact),
			rule.NewFact("Out2", []term.Term{hmacK}, rule.LinearFact),
			rule.NewFact("State1", []term.Term{m, k}, rule.LinearFact),
		},
		Attrs: make(map[string]rule.Attribute),
	}

	// Order B: Out(hmac(k)) before Out(hash(m)).
	rB := &rule.Rule{
		Name: "R",
		LHS:  lhs,
		Act:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("Out2", []term.Term{hmacK}, rule.LinearFact),
			rule.NewFact("Out", []term.Term{hashM}, rule.LinearFact),
			rule.NewFact("State1", []term.Term{m, k}, rule.LinearFact),
		},
		Attrs: make(map[string]rule.Attribute),
	}

	rulesA := rule.Translate(rA)
	rulesB := rule.Translate(rB)

	require.Len(t, rulesA, 1, "Depth-1 decomposition should produce a single rule")
	require.Len(t, rulesB, 1, "Depth-1 decomposition should produce a single rule")

	// The RHS fact ordering faithfully mirrors the original rule, so it may
	// differ. What must be stable is the trigger attribute.
	trigA := rulesA[0].Attrs[rule.TriggerAttributeName]
	trigB := rulesB[0].Attrs[rule.TriggerAttributeName]
	require.Equal(t, fmt.Sprint(trigA), fmt.Sprint(trigB),
		"Depth-1 trigger attributes differ between RHS orderings")
}

// normalizedRuleBodies strips the rule name from each rule's string
// representation so that mid-rule numbering (R_0 vs R_1) does not
// affect comparison. The attributes, facts, and generated variable
// names are preserved.
func normalizedRuleBodies(rules []*rule.Rule) []string {
	bodies := make([]string, len(rules))
	for i, r := range rules {
		s := r.String()
		// Format: "rule NAME ...:\n  body"
		// Strip "rule NAME" prefix, keep attributes and body.
		if idx := strings.Index(s, " ["); idx >= 0 {
			bodies[i] = s[idx:]
		} else if idx := strings.Index(s, ":\n"); idx >= 0 {
			bodies[i] = s[idx:]
		} else {
			bodies[i] = s
		}
	}
	return bodies
}

// assertRulesEqual compares two rule slices, handling ordering and formatting differences.
func assertRulesEqual(t *testing.T, expected, actual []*rule.Rule) {
	require.Len(t, actual, len(expected), "Different number of rules")

	// Sort rules by name for consistent comparison
	sortRulesByName := func(rules []*rule.Rule) []*rule.Rule {
		sorted := make([]*rule.Rule, len(rules))
		copy(sorted, rules)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Name < sorted[j].Name
		})
		return sorted
	}

	expectedSorted := sortRulesByName(expected)
	actualSorted := sortRulesByName(actual)

	for i := range expectedSorted {
		expectedRule := expectedSorted[i]
		actualRule := actualSorted[i]

		// Compare rule names
		require.Equal(t, expectedRule.Name, actualRule.Name,
			"Rule %d: Name mismatch", i)

		// Compare LHS, Act, RHS lengths
		require.Len(t, actualRule.LHS, len(expectedRule.LHS),
			"Rule %s: LHS length mismatch", expectedRule.Name)
		require.Len(t, actualRule.Act, len(expectedRule.Act),
			"Rule %s: Act length mismatch", expectedRule.Name)
		require.Len(t, actualRule.RHS, len(expectedRule.RHS),
			"Rule %s: RHS length mismatch", expectedRule.Name)

		// For more detailed comparison, we could implement structural equality.
		// For now, comparing the string representation should be sufficient.
		require.Equal(t, expectedRule.String(), actualRule.String(),
			"Rule %s: Content mismatch", expectedRule.Name)
	}
}

// carriedTupleTestRules are source rules whose split-rule chains carry
// public variables: nested below the first of several computations, at
// increasing depths, under a shared subterm, and in the premise.
var carriedTupleTestRules = map[string]string{
	"nested below the first computation": `
rule Send:
  let c = senc(cat(byte('0x62'), byte($body)), k)
      s = hmac(k, messageis(c, k))
  in [Key(k)] --[Compute(<s>)]-> [Sent(c)]`,
	"in the premise": `
rule Send:
  let c = senc(m, k)
      s = hmac(k, messageis(c, k))
  in [Key(k, $p)] --[Compute(<s, $p>)]-> [Done(s)]`,
	"depth 1": `
rule R: [St(k)] --> [Out(h(g(k), $x))]`,
	"depth 2": `
rule R: [St(k)] --> [Out(h(g(k, $x)))]`,
	"depth 3": `
rule R: [St(k)] --> [Out(h(g(f(k, $x))))]`,
	"shared subterm": `
rule R: [St(k)] --> [Out(h(g(f(k, $x))), i(g(f(k, $x))))]`,
	"premise and term": `
rule R: [St($p, k)] --> [Out(h(g(f(k, $x)), $p))]`,
	"repeated": `
rule R: [St($p, k)] --> [Out(h(g(k, $x, $x, $p)), $x)]`,
}

// assertCarriedTuplesConsistent checks that every ST_ fact is produced and
// consumed with the same carried tuple, its first argument.
func assertCarriedTuplesConsistent(t *testing.T, rules []*rule.Rule) int {
	t.Helper()
	prefix := rule.SubtermName + rule.ComponentSep
	tuples := map[string]map[string]bool{}
	produced, consumed := map[string]bool{}, map[string]bool{}
	record := func(facts []*rule.Fact, side map[string]bool) {
		for _, f := range facts {
			if !strings.HasPrefix(f.Name, prefix) || len(f.Args) == 0 {
				continue
			}
			if tuples[f.Name] == nil {
				tuples[f.Name] = map[string]bool{}
			}
			tuples[f.Name][f.Args[0].String()] = true
			side[f.Name] = true
		}
	}
	for _, r := range rules {
		record(r.LHS, consumed)
		record(r.RHS, produced)
	}
	for name, carried := range tuples {
		if len(carried) != 1 || !produced[name] || !consumed[name] {
			t.Errorf("%s: carried tuples %v, produced %t, consumed %t", name, carried, produced[name], consumed[name])
		}
	}
	return len(tuples)
}

func TestTranslateCarriesPublicVariablesConsistently(t *testing.T) {
	t.Parallel()

	for name, source := range carriedTupleTestRules {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "rules.spthy")
			spec := "theory Carried\nbegin\n" + source + "\nend\n"
			if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
				t.Fatalf("write specification: %v", err)
			}
			processed, err := cmd.ProcessRules(context.Background(), path, "", true, nil)
			if err != nil {
				t.Fatalf("process rules: %v", err)
			}
			if assertCarriedTuplesConsistent(t, processed.Executable) == 0 {
				t.Fatalf("no split rules generated: %v", processed.Executable)
			}
		})
	}
}
