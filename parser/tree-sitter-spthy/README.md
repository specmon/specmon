# tree-sitter-spthy

Parser for the spthy language of the Tamarin prover, vendored for the
SpecMon parser package.

- `grammar.json`, `node-types.json` and `scanner.c` come from the
  tree-sitter-spthy grammar in the Tamarin prover repository
  (<https://github.com/tamarin-prover/tamarin-prover>, directory
  `tree-sitter/tree-sitter-spthy`). SpecMon changed the grammar in #13
  and #40.
- `parser.c` is generated from `grammar.json` by tree-sitter v0.25.3.
- `tree_sitter/` contains the tree-sitter runtime headers.
- `binding.go` is the Go binding of SpecMon and is licensed under the
  AGPL-3.0 like the rest of SpecMon.

`LICENSE` lists the licenses of all other files in this directory.
