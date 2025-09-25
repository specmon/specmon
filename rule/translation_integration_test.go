package rule_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/specmon/specmon/cmd"
	"github.com/specmon/specmon/parser"
	"github.com/specmon/specmon/rule"
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

// assertRulesEqual compares two rule slices, handling ordering and formatting differences.
func assertRulesEqual(t *testing.T, expected, actual []*rule.Rule) {
	require.Equal(t, len(expected), len(actual), "Different number of rules")

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
		require.Equal(t, len(expectedRule.LHS), len(actualRule.LHS),
			"Rule %s: LHS length mismatch", expectedRule.Name)
		require.Equal(t, len(expectedRule.Act), len(actualRule.Act),
			"Rule %s: Act length mismatch", expectedRule.Name)
		require.Equal(t, len(expectedRule.RHS), len(actualRule.RHS),
			"Rule %s: RHS length mismatch", expectedRule.Name)

		// For more detailed comparison, we could implement structural equality.
		// For now, comparing the string representation should be sufficient.
		require.Equal(t, expectedRule.String(), actualRule.String(),
			"Rule %s: Content mismatch", expectedRule.Name)
	}
}
