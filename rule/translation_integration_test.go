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
			_, _, actualRules, err := cmd.ProcessRules(inputPath, "", true, nil)
			require.NoError(t, err, "Failed to process input rules")

			// Compare rules
			assertRulesEqual(t, expectedRules, actualRules)
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

	for i := 0; i < len(expectedSorted); i++ {
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
