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

package parser

import (
	"context"
	"strings"
	"testing"
)

// runPreprocessor parses src with the spthy grammar and applies the
// preprocessor with the given defines, returning the resulting source.
func runPreprocessor(t *testing.T, src string, defines []string) string {
	t.Helper()

	tree, err := Parse(context.Background(), []byte(src))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	pp := NewPreprocessor([]byte(src), defines)
	return string(pp.Run(tree.RootNode()))
}

// theoryWithIfdef wraps an #ifdef block in a minimal theory so the
// tree-sitter grammar accepts it. The consequence and alternative are
// distinguished by formal comments whose identifiers we check for in
// the preprocessed output.
func theoryWithIfdef(condition string) string {
	return "theory T begin\n" +
		"#ifdef " + condition + "\n" +
		"OnConseq {* on *}\n" +
		"#else\n" +
		"OnAlt {* off *}\n" +
		"#endif\n" +
		"end\n"
}

func TestPreprocessorIfdef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		condition  string
		defines    []string
		wantConseq bool
	}{
		{
			name:       "bare ident defined",
			condition:  "MONITOR",
			defines:    []string{"MONITOR"},
			wantConseq: true,
		},
		{
			name:       "bare ident undefined",
			condition:  "MONITOR",
			defines:    nil,
			wantConseq: false,
		},
		{
			name:       "not undefined",
			condition:  "not MONITOR",
			defines:    nil,
			wantConseq: true,
		},
		{
			name:       "not defined",
			condition:  "not MONITOR",
			defines:    []string{"MONITOR"},
			wantConseq: false,
		},
		{
			name:       "and both defined",
			condition:  "Properties & Sanity",
			defines:    []string{"Properties", "Sanity"},
			wantConseq: true,
		},
		{
			name:       "and one missing",
			condition:  "Properties & Sanity",
			defines:    []string{"Properties"},
			wantConseq: false,
		},
		{
			name:       "or one defined",
			condition:  "Properties | Sanity",
			defines:    []string{"Sanity"},
			wantConseq: true,
		},
		{
			name:       "or neither defined",
			condition:  "Properties | Sanity",
			defines:    nil,
			wantConseq: false,
		},
		{
			name:       "parenthesised grouping selects or-branch",
			condition:  "(Properties | Sanity) & not Release",
			defines:    []string{"Sanity"},
			wantConseq: true,
		},
		{
			name:       "parenthesised grouping blocked by negation",
			condition:  "(Properties | Sanity) & not Release",
			defines:    []string{"Sanity", "Release"},
			wantConseq: false,
		},
		{
			name:       "compound positive and negative",
			condition:  "Properties & not Sanity",
			defines:    []string{"Properties"},
			wantConseq: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := theoryWithIfdef(tc.condition)
			out := runPreprocessor(t, src, tc.defines)

			hasConseq := strings.Contains(out, "OnConseq")
			hasAlt := strings.Contains(out, "OnAlt")

			if tc.wantConseq && !hasConseq {
				t.Errorf("condition %q with defines %v: expected consequence; output:\n%s",
					tc.condition, tc.defines, out)
			}
			if tc.wantConseq && hasAlt {
				t.Errorf("condition %q with defines %v: alternative should be omitted; output:\n%s",
					tc.condition, tc.defines, out)
			}
			if !tc.wantConseq && !hasAlt {
				t.Errorf("condition %q with defines %v: expected alternative; output:\n%s",
					tc.condition, tc.defines, out)
			}
			if !tc.wantConseq && hasConseq {
				t.Errorf("condition %q with defines %v: consequence should be omitted; output:\n%s",
					tc.condition, tc.defines, out)
			}
		})
	}
}
