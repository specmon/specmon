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

The test runs each input through `cmd.ProcessRules` with decomposition and without a role, as the root command does. To see the result for your input, run:

```bash
go run . testdata/translation/your_test_case/input.spthy
```

Copy the printed rules into `expected.spthy` without their indentation, between the `theory`, `begin` and `end` lines of the input.

Before decomposition, a conclusion that no premise consumes is dropped, and a function call in it stays as a `Compute_(...)` fact. To keep a conclusion in the expected rules, let a premise consume it.

## Existing Test Cases

- **simple_function**: Tests decomposition of nested function calls `len(hash(m))`
- **no_decomposition**: Tests that a rule without function applications is not decomposed; no rule consumes its conclusion, so the conclusion is dropped
- **no_decomp_attribute**: Tests rules with the `[no-decomp]` attribute
- **existing_triggers**: Tests that rules with existing triggers should NOT be decomposed
- **existing_hints**: Tests that rules with existing hints should NOT be decomposed

## Running Tests

```bash
go test -v ./rule -run TestTranslationFromFiles
```

This will automatically discover and run all test cases in the `testdata/translation/` directory.
