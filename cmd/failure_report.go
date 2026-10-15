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
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/specmon/specmon/monitor"
)

// writeFailureReport writes why the candidates and branches failed: every
// record of the rejected event, the retained records of earlier events as
// context, and the counts per category.
func writeFailureReport(w io.Writer, report monitor.FailureReport) {
	var b strings.Builder
	b.WriteString("failed candidates and branches at the rejected event:\n")
	for _, record := range report.Final {
		writeFailureRecord(&b, record)
	}

	counts := report.Counts
	total := counts.NoCandidate + counts.Restriction + counts.Evaluation + counts.EpsilonDepth + counts.DeadHint
	if earlier := total - len(report.Final); earlier > 0 {
		fmt.Fprintf(&b, "earlier failures, as context (the most recent %d of %d):\n", len(report.Earlier), earlier)
		for _, record := range report.Earlier {
			writeFailureRecord(&b, record)
		}
	}
	var categories []string
	for _, category := range []struct {
		name  string
		count int
	}{
		{"no_candidate", counts.NoCandidate},
		{"restriction", counts.Restriction},
		{"evaluation", counts.Evaluation},
		{"epsilon_depth", counts.EpsilonDepth},
		{"dead_hint", counts.DeadHint},
	} {
		if category.count > 0 {
			categories = append(categories, fmt.Sprintf("%s %d", category.name, category.count))
		}
	}
	fmt.Fprintf(&b, "failure counts: %s\n", strings.Join(categories, ", "))

	_, _ = io.WriteString(w, b.String())
}

func writeFailureRecord(b *strings.Builder, record monitor.FailureRecord) {
	fmt.Fprintf(b, "  %s event %d", record.Monitor, record.Event)
	if record.Rewrite != nil {
		fmt.Fprintf(b, " (raw event %d, alternative %d, position %d)",
			record.Rewrite.RawEvent, record.Rewrite.Alternative, record.Rewrite.Position)
	}
	fmt.Fprintf(b, " branch %016x: ", record.Branch)
	if record.Rule != "" {
		fmt.Fprintf(b, "rule %s: ", escapeControl(record.Rule))
	}
	fmt.Fprintf(b, "%s: %s\n", record.Category, escapeControl(record.Message))
}

// escapeControl escapes the control characters of s, which can come from
// the trace, so that a record stays on one line of the report.
func escapeControl(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// writeRejectionReport writes the failure report of m if err is a
// rejection that is not a violation.
func writeRejectionReport(w io.Writer, err error, m *monitor.Monitor) {
	if errors.Is(err, monitor.ErrNoApplicableRule) {
		writeFailureReport(w, m.FailureReport())
	}
}
