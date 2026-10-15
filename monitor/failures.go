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

package monitor

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// FailureHistoryCap is the number of records of earlier events that a
// monitor keeps. The records of the current event are not capped, and the
// counts per category cover the whole invocation.
const FailureHistoryCap = 256

// Names of the monitors in a FailureRecord.
const (
	// FailureMonitorCore is the monitor of the protocol model.
	FailureMonitorCore = "core"
	// FailureMonitorRewrite is the rewriter of the integrated pipeline or
	// of the rewrite command.
	FailureMonitorRewrite = "rewrite"
)

// FailureCategory says why a rule candidate or a branch ended.
type FailureCategory string

const (
	// FailureNoCandidate: no candidate of any rule consumes the event in
	// the branch. The record names no rule.
	FailureNoCandidate FailureCategory = "no_candidate"
	// FailureRestriction: an Eq or Neq restriction of a candidate failed.
	FailureRestriction FailureCategory = "restriction"
	// FailureEvaluation: a term of a candidate that matched the event
	// could not be evaluated.
	FailureEvaluation FailureCategory = "evaluation"
	// FailureEpsilonDepth: an epsilon candidate is left after an epsilon
	// step, so the successor is pruned.
	FailureEpsilonDepth FailureCategory = "epsilon_depth"
	// FailureDeadHint: a hinted start has no continuation that consumes
	// the event.
	FailureDeadHint FailureCategory = "dead_hint"
)

// RewritePosition identifies a rewritten event in the integrated pipeline.
type RewritePosition struct {
	// RawEvent is the index of the raw event, from 1, in the count of the
	// rewriter.
	RawEvent int `json:"raw_event"`
	// Alternative is the index, from 1, of the rewrite application of the
	// raw event that emitted the rewritten event.
	Alternative int `json:"alternative"`
	// Position is the index, from 1, of the rewritten event among the
	// events that the alternative emits.
	Position int `json:"position"`
}

// FailureRecord is the reason why a rule candidate or a branch ended at an
// event. A failure is recorded whether or not other branches survive.
type FailureRecord struct {
	// Monitor is FailureMonitorRewrite or FailureMonitorCore.
	Monitor string `json:"monitor"`
	// Event is the index, from 1, of the event among all events that the
	// monitor received in this invocation. For the core monitor it counts
	// as ViolationInfo.EventIndex does: pre-trace included and, in the
	// pipeline, the rewritten events. The rewrite alternatives of one raw
	// event count their outputs from the same index, so their records can
	// share it. Rewrite tells them apart.
	Event int `json:"event"`
	// Rewrite identifies the rewritten event of a core record in the
	// pipeline. It is nil otherwise.
	Rewrite *RewritePosition `json:"rewrite,omitempty"`
	// Rule is the name of the rule whose candidate failed. It is empty for
	// FailureNoCandidate.
	Rule     string          `json:"rule,omitempty"`
	Category FailureCategory `json:"category"`
	Message  string          `json:"message"`
	// Branch is the hash of the configuration in which the event was
	// tried. It is encoded as 16 hexadecimal digits.
	Branch uint64 `json:"-"`
	// Cause is the error of the failure, if there is one.
	Cause error `json:"-"`
}

// MarshalJSON encodes the record with its branch in hexadecimal.
func (r FailureRecord) MarshalJSON() ([]byte, error) {
	type fields FailureRecord
	return json.Marshal(struct {
		fields
		Branch string `json:"branch"`
	}{fields(r), fmt.Sprintf("%016x", r.Branch)})
}

// FailureCounts counts records per category. Missing JSON counts are zero.
type FailureCounts struct {
	NoCandidate  int `json:"no_candidate,omitempty"`
	Restriction  int `json:"restriction,omitempty"`
	Evaluation   int `json:"evaluation,omitempty"`
	EpsilonDepth int `json:"epsilon_depth,omitempty"`
	DeadHint     int `json:"dead_hint,omitempty"`
}

func (c *FailureCounts) add(category FailureCategory) {
	switch category {
	case FailureNoCandidate:
		c.NoCandidate++
	case FailureRestriction:
		c.Restriction++
	case FailureEvaluation:
		c.Evaluation++
	case FailureEpsilonDepth:
		c.EpsilonDepth++
	case FailureDeadHint:
		c.DeadHint++
	}
}

// FailureReport is what a rejection reports about failed candidates and
// branches. The records of the final event explain the rejection. The
// earlier records are context, not its cause.
type FailureReport struct {
	// Final holds every record of the event that was rejected. In the
	// pipeline, of every alternative of the raw event.
	Final []FailureRecord `json:"final"`
	// Earlier holds the most recent records of earlier events, oldest
	// first, at most FailureHistoryCap.
	Earlier []FailureRecord `json:"earlier"`
	// Counts covers every record of the invocation, including evicted
	// ones: all runs, and in the pipeline both monitors.
	Counts FailureCounts `json:"counts"`
}

// failureLog keeps the records of an invocation: all records of the
// current event, the most recent records of earlier events and the counts
// per category. Apart from the current event, its memory is bounded.
type failureLog struct {
	current []FailureRecord
	earlier []FailureRecord
	counts  FailureCounts
}

// beginEvent moves the records of the current event to the earlier
// records, which keep only the most recent FailureHistoryCap of them.
func (l *failureLog) beginEvent() {
	l.earlier = append(l.earlier, l.current[max(0, len(l.current)-FailureHistoryCap):]...)
	if excess := len(l.earlier) - FailureHistoryCap; excess > 0 {
		l.earlier = l.earlier[excess:]
	}
	clear(l.current)
	l.current = l.current[:0]
}

func (l *failureLog) add(record FailureRecord) {
	l.current = append(l.current, record)
	l.counts.add(record.Category)
}

func (l *failureLog) report() FailureReport {
	return FailureReport{
		Final:   append(make([]FailureRecord, 0, len(l.current)), l.current...),
		Earlier: append(make([]FailureRecord, 0, len(l.earlier)), l.earlier...),
		Counts:  l.counts,
	}
}

// failureSite is where a monitor makes the records of the current event.
type failureSite struct {
	monitor string
	event   int
	// rewrite is the rewritten event in the pipeline. Its RawEvent is 0
	// otherwise. It is kept by value, so that only a record allocates.
	rewrite RewritePosition
	// branch is the configuration in which the event is tried. Its hash is
	// computed only for a record, since the engine does not always need it.
	branch *Config
}

// beginEvent starts the next event of m. The records of the previous event
// become earlier records.
func (m *Monitor) beginEvent() {
	m.failures.beginEvent()
	m.site.event++
	m.site.rewrite = RewritePosition{}
}

// recordFailure records why a candidate of the named rule, or the branch
// if ruleName is empty, ended at the current event.
func (m *Monitor) recordFailure(category FailureCategory, ruleName, message string, cause error) {
	var branch uint64
	if m.site.branch != nil {
		branch = m.site.branch.Hash()
	}

	var rewrite *RewritePosition
	if m.site.rewrite.RawEvent > 0 {
		position := m.site.rewrite
		rewrite = &position
	}

	m.failures.add(FailureRecord{
		Monitor:  m.site.monitor,
		Event:    m.site.event,
		Rewrite:  rewrite,
		Rule:     ruleName,
		Category: category,
		Message:  message,
		Branch:   branch,
		Cause:    cause,
	})
}

// recordLocalFailure records err for a candidate of r if err ends only
// that candidate: a failed restriction, a failed evaluation or an epsilon
// candidate left after the epsilon step. It reports whether err was such
// a local failure. Any other error shows a broken invariant and ends the
// processing of the event.
//
// Only candidates that matched the event are recorded. A failed evaluation
// while a trigger or hint is matched against the event means that the
// candidate does not match, like any other unification error.
func (m *Monitor) recordLocalFailure(r *rule.Rule, err error) bool {
	var category FailureCategory
	switch {
	case errors.Is(err, ErrRestrictionViolated):
		category = FailureRestriction
	case errors.Is(err, term.ErrEvaluation):
		category = FailureEvaluation
	case errors.Is(err, ErrEpsilonDepth):
		category = FailureEpsilonDepth
	default:
		return false
	}
	m.recordFailure(category, r.Name, err.Error(), err)
	return true
}

// FailureReport reports the records of the last event, the retained
// records of earlier events and the counts. After a rejection that is not
// a violation, an event that no rewrite rule accepts, it explains that
// rejection.
func (m *Monitor) FailureReport() FailureReport {
	return m.failures.report()
}
