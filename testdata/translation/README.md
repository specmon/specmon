# Translation Test Cases

This directory contains test cases for testing the rule decomposition/translation functionality.

## Structure

Each test case is a directory under `testdata/translation/` with the following structure:

```
testdata/translation/
├── <test_case_name>/
│   ├── input.spthy          # Original rules to be decomposed
│   └── expected.spthy       # Expected decomposed rules
├── README.md                # This documentation (ignored by tests)
```

**Note**: Only directories are processed as test cases. Files like README.md are automatically ignored.

## Adding New Test Cases

1. Create a new directory under `testdata/translation/` with a descriptive name
2. Add `input.spthy` with the original rule(s) you want to test
3. Add `expected.spthy` with the expected decomposed rules

### How to Generate Expected Output

To see what the actual decomposition produces for your input, you can:

1. Temporarily add a debug test in `rule/translation_integration_test.go`:

```go
func TestDebugNewCase(t *testing.T) {
    inputFile := "../testdata/translation/your_test_case/input.spthy"
    _, _, decompRules, err := cmd.ProcessRules(inputFile, "", true, nil)
    require.NoError(t, err)
    
    fmt.Println("Decomposed rules:")
    for i, rule := range decompRules {
        fmt.Printf("Rule %d: %s\n", i, rule.String())
        fmt.Println("---")
    }
}
```

2. Run the test: `go test -v ./rule -run TestDebugNewCase`
3. Copy the output to create your `expected.spthy` file
4. Remove the debug test

## Existing Test Cases

- **simple_function**: Tests decomposition of nested function calls `len(hash(m))`
- **no_decomposition**: Tests rules that don't need decomposition
- **no_decomp_attribute**: Tests rules with the `[no-decomp]` attribute
- **existing_triggers**: Tests that rules with existing triggers should NOT be decomposed
- **existing_hints**: Tests that rules with existing hints should NOT be decomposed

## Running Tests

```bash
go test -v ./rule -run TestTranslationFromFiles
```

This will automatically discover and run all test cases in the `testdata/translation/` directory.
