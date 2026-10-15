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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

const (
	failureSeedEvent  = "failureSeed"
	failureCheckEvent = "failureCheck"
	failureTickEvent  = "failureTick"
	failureStopEvent  = "failureStop"
	failureValue      = "FailureValue"
	failureReady      = "FailureReady"
)

func failureUnit() term.Term {
	return term.NewFunction(term.PairFunctionName, nil)
}

func failureInt(value int64) term.Term {
	return term.NewConstant(value)
}

// failureSeedRule consumes the seed event and produces FailureValue(v)
// for each value.
func failureSeedRule(values ...int64) *rule.Rule {
	var rhs []*rule.Fact
	for _, value := range values {
		rhs = append(rhs, linearFact(failureValue, failureInt(value)))
	}
	return triggerRule("FailureSeed", nil, rhs, nil, eventTerm(failureSeedEvent, failureUnit()))
}

// failureCheckRule consumes a FailureValue(v) on the check event <x> if
// v = x and puts it back.
func failureCheckRule() *rule.Rule {
	v := term.NewVariable("v")
	x := term.NewVariable("x")
	return triggerRule("FailureCheck",
		[]*rule.Fact{linearFact(failureValue, v)},
		[]*rule.Fact{linearFact(failureValue, v)},
		[]*rule.Fact{equalAction(v, x)},
		eventTerm(failureCheckEvent, x))
}

func processFailureEvent(t *testing.T, m *Monitor, event term.Term) {
	t.Helper()
	if _, err := m.ProcessEvent(event); err != nil {
		t.Fatalf("ProcessEvent(%s): %v", event, err)
	}
}

func failureTrace(t *testing.T, events ...term.Term) io.ReadCloser {
	t.Helper()
	var b strings.Builder
	for i, event := range events {
		fn, ok := event.(*term.Function)
		if !ok {
			t.Fatalf("event %s is not a function", event)
		}
		line, err := json.Marshal(&TimedEvent{Time: int64(i + 1), Event: fn})
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return io.NopCloser(strings.NewReader(b.String()))
}

func runFailureTrace(t *testing.T, m *Monitor, events ...term.Term) *ViolationInfo {
	t.Helper()
	violation, err := m.Run(context.Background(), failureTrace(t, events...), nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return violation
}

// wantViolation runs events through m and returns the violation that it
// must report.
func wantViolation(t *testing.T, m *Monitor, events ...term.Term) *ViolationInfo {
	t.Helper()
	violation := runFailureTrace(t, m, events...)
	if violation == nil {
		t.Fatal("no violation, want one")
	}
	return violation
}

// wantFailures checks the counts per category of the failures that m
// recorded.
func wantFailures(t *testing.T, m *Monitor, want FailureCounts) {
	t.Helper()
	if got := m.failures.counts; got != want {
		t.Errorf("failures = %+v, want %+v", got, want)
	}
}

func configHashes(m *Monitor) []uint64 {
	var hashes []uint64
	for _, c := range m.Configs() {
		hashes = append(hashes, c.Hash())
	}
	slices.Sort(hashes)
	return hashes
}

// recordSummary is the part of a record that the tests compare.
type recordSummary struct {
	monitor  string
	event    int
	rewrite  RewritePosition
	rule     string
	category FailureCategory
}

func (s recordSummary) String() string {
	return fmt.Sprintf("%s event %d %v %q %s", s.monitor, s.event, s.rewrite, s.rule, s.category)
}

func summarize(records []FailureRecord) []recordSummary {
	summaries := make([]recordSummary, 0, len(records))
	for _, record := range records {
		summary := recordSummary{
			monitor: record.Monitor, event: record.Event,
			rule: record.Rule, category: record.Category,
		}
		if record.Rewrite != nil {
			summary.rewrite = *record.Rewrite
		}
		summaries = append(summaries, summary)
	}
	return summaries
}

func wantRecords(t *testing.T, what string, got []FailureRecord, want ...recordSummary) {
	t.Helper()
	if !slices.Equal(summarize(got), want) {
		t.Fatalf("%s records = %v, want %v", what, summarize(got), want)
	}
}

func core(event int, ruleName string, category FailureCategory) recordSummary {
	return recordSummary{monitor: FailureMonitorCore, event: event, rule: ruleName, category: category}
}

func TestFailureRecordsRestrictionBesideSurvivor(t *testing.T) {
	m := newEpsilonTestMonitor(t, failureSeedRule(1, 2), failureCheckRule())
	processFailureEvent(t, m, eventTerm(failureSeedEvent, failureUnit()))
	branches := configHashes(m)
	processFailureEvent(t, m, eventTerm(failureCheckEvent, failureInt(1)))

	if len(m.Configs()) != 1 {
		t.Fatalf("configurations = %d, want the one that checked FailureValue(1)", len(m.Configs()))
	}
	report := m.failures.report()
	wantRecords(t, "current", report.Final, core(2, "FailureCheck", FailureRestriction))
	record := report.Final[0]
	if !errors.Is(record.Cause, ErrRestrictionViolated) || !strings.Contains(record.Message, "restriction violated") {
		t.Fatalf("record cause %v, message %q, want the violated restriction", record.Cause, record.Message)
	}
	if len(branches) != 1 || record.Branch != branches[0] {
		t.Fatalf("record branch %d, want the configuration before the event %v", record.Branch, branches)
	}
	if report.Counts != (FailureCounts{Restriction: 1}) {
		t.Fatalf("counts = %+v, want one restriction", report.Counts)
	}
}

func TestFailureRecordsBranchWithoutCandidate(t *testing.T) {
	const nextEvent = "failureNext"
	seedA := triggerRule("FailureSeedA", nil, []*rule.Fact{linearFact("FailureA")}, nil, eventTerm(failureSeedEvent, failureUnit()))
	seedB := triggerRule("FailureSeedB", nil, []*rule.Fact{linearFact("FailureB")}, nil, eventTerm(failureSeedEvent, failureUnit()))
	useA := triggerRule("FailureUseA", []*rule.Fact{linearFact("FailureA")}, nil, nil, eventTerm(nextEvent, failureUnit()))
	m := newEpsilonTestMonitor(t, seedA, seedB, useA)

	violation := runFailureTrace(t, m,
		eventTerm(failureSeedEvent, failureUnit()),
		eventTerm(nextEvent, failureUnit()),
		eventTerm(nextEvent, failureUnit()))
	if violation == nil || violation.EventIndex != 3 {
		t.Fatalf("violation = %+v, want one at event 3", violation)
	}
	report := violation.Failures
	wantRecords(t, "final", report.Final, core(3, "", FailureNoCandidate))
	wantRecords(t, "earlier", report.Earlier, core(2, "", FailureNoCandidate))
	if report.Final[0].Rule != "" || report.Final[0].Cause != nil {
		t.Fatalf("no-candidate record names rule %q, cause %v", report.Final[0].Rule, report.Final[0].Cause)
	}
	if report.Earlier[0].Branch == report.Final[0].Branch {
		t.Fatal("the branch that ended at event 2 and the one that ended at event 3 have the same hash")
	}
	if report.Counts != (FailureCounts{NoCandidate: 2}) {
		t.Fatalf("counts = %+v, want two branches without a candidate", report.Counts)
	}
}

// TestFailureRecordsOfEachCategory checks the records of a rejected event
// for each category of a rule candidate: the event, the rule and the
// cause, whose text is the message. A depth record names the epsilon rule
// whose application reached the pruned successor, and its message names
// the candidate left in it.
func TestFailureRecordsOfEachCategory(t *testing.T) {
	const (
		otherEvent  = "failureOther"
		hintedEvent = "failureHinted"
	)
	x := term.NewVariable("x")
	y := term.NewVariable("y")
	two := failureInt(2)
	seedEvent := eventTerm(failureSeedEvent, failureUnit())
	seed := triggerRule("FailureSeed", nil, []*rule.Fact{linearFact(failureReady, failureInt(1))}, nil, seedEvent)
	ready := []*rule.Fact{linearFact(failureReady, x)}

	for _, test := range []struct {
		name   string
		rules  []*rule.Rule
		events []term.Term
		want   []recordSummary
		cause  error
		// messages are parts of the messages of the records in want.
		messages []string
	}{
		{
			name:   "restriction in the epsilon step",
			rules:  []*rule.Rule{seed, epsilonRule("FailureEpsilon", ready, nil, []*rule.Fact{equalAction(x, two)})},
			events: []term.Term{seedEvent},
			want:   []recordSummary{core(1, "FailureEpsilon", FailureRestriction)},
			cause:  ErrRestrictionViolated,
		},
		{
			name: "restriction in a native completion",
			rules: []*rule.Rule{triggerRule("FailureNative", nil, nil, []*rule.Fact{equalAction(x, y)},
				eventTerm(failureCheckEvent, x), eventTerm(otherEvent, y))},
			events: []term.Term{eventTerm(failureCheckEvent, failureInt(1)), eventTerm(otherEvent, two)},
			want:   []recordSummary{core(2, "FailureNative", FailureRestriction)},
			cause:  ErrRestrictionViolated,
		},
		{
			name:   "restriction in a hinted start",
			rules:  []*rule.Rule{seed, hintRule("FailureHinted", ready, nil, []*rule.Fact{equalAction(x, y)}, eventTerm(hintedEvent, y))},
			events: []term.Term{seedEvent, eventTerm(hintedEvent, two)},
			want:   []recordSummary{core(2, "FailureHinted", FailureRestriction)},
			cause:  ErrRestrictionViolated,
		},
		{
			name: "evaluation",
			rules: []*rule.Rule{triggerRule("FailureEvaluation", nil, []*rule.Fact{linearFact(failureValue, branchTestOverflow())}, nil,
				seedEvent)},
			events: []term.Term{seedEvent},
			want:   []recordSummary{core(1, "FailureEvaluation", FailureEvaluation)},
			cause:  term.ErrEvaluation,
		},
		{
			// Each epsilon rule leaves the other one applicable.
			name: "epsilon depth",
			rules: []*rule.Rule{
				triggerRule("FailureStart", nil, []*rule.Fact{linearFact("FailureA"), linearFact("FailureC")}, nil, seedEvent),
				epsilonRule("FailureConsumeA", []*rule.Fact{linearFact("FailureA")}, nil, nil),
				epsilonRule("FailureConsumeC", []*rule.Fact{linearFact("FailureC")}, nil, nil),
			},
			events:   []term.Term{seedEvent},
			want:     []recordSummary{core(1, "FailureConsumeA", FailureEpsilonDepth), core(1, "FailureConsumeC", FailureEpsilonDepth)},
			cause:    ErrEpsilonDepth,
			messages: []string{"rule FailureConsumeC", "rule FailureConsumeA"},
		},
		{
			name: "dead hint",
			rules: []*rule.Rule{seed, hintRule("FailureHinted", ready, []*rule.Fact{linearFact("FailureStarted", y)}, nil,
				eventTerm(hintedEvent, y))},
			events:   []term.Term{seedEvent, eventTerm(hintedEvent, two)},
			want:     []recordSummary{core(2, "FailureHinted", FailureDeadHint)},
			messages: []string{"after accepting hint"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			final := wantViolation(t, newEpsilonTestMonitor(t, test.rules...), test.events...).Failures.Final
			wantRecords(t, "final", final, test.want...)
			for i, record := range final {
				if !errors.Is(record.Cause, test.cause) || (record.Cause != nil && record.Message != record.Cause.Error()) {
					t.Fatalf("record %+v, want the cause %v as its message", record, test.cause)
				}
				if i < len(test.messages) && !strings.Contains(record.Message, test.messages[i]) {
					t.Fatalf("record message %q, want %q", record.Message, test.messages[i])
				}
			}
		})
	}
}

// failureTickMonitor returns a monitor in which every tick event leaves
// one restriction record beside the branch that survives it.
func failureTickMonitor(t *testing.T) *Monitor {
	t.Helper()
	x := term.NewVariable("x")
	keep := triggerRule("FailureKeep", nil, nil, nil, eventTerm(failureTickEvent, x))
	fail := triggerRule("FailureFail", nil, nil, []*rule.Fact{equalAction(x, failureInt(0))}, eventTerm(failureTickEvent, x))
	return newEpsilonTestMonitor(t, keep, fail)
}

func TestFailureHistoryCap(t *testing.T) {
	for _, earlier := range []int{FailureHistoryCap - 1, FailureHistoryCap, FailureHistoryCap + 1, 4 * FailureHistoryCap} {
		t.Run(fmt.Sprint(earlier), func(t *testing.T) {
			m := failureTickMonitor(t)
			events := make([]term.Term, 0, earlier+1)
			for i := range earlier {
				events = append(events, eventTerm(failureTickEvent, failureInt(int64(i+1))))
			}
			events = append(events, eventTerm(failureStopEvent, failureUnit()))
			violation := runFailureTrace(t, m, events...)
			if violation == nil || violation.EventIndex != earlier+1 {
				t.Fatalf("violation = %+v, want one at event %d", violation, earlier+1)
			}

			report := violation.Failures
			wantRecords(t, "final", report.Final, core(earlier+1, "", FailureNoCandidate))
			kept := min(earlier, FailureHistoryCap)
			want := make([]recordSummary, 0, kept)
			for event := earlier - kept + 1; event <= earlier; event++ {
				want = append(want, core(event, "FailureFail", FailureRestriction))
			}
			wantRecords(t, "earlier", report.Earlier, want...)
			if report.Counts != (FailureCounts{NoCandidate: 1, Restriction: earlier}) {
				t.Fatalf("counts = %+v, want %d restrictions and one branch without a candidate", report.Counts, earlier)
			}
		})
	}
}

func TestFailureRecordsOfCurrentEventAreNotCapped(t *testing.T) {
	values := make([]int64, FailureHistoryCap+44)
	for i := range values {
		values[i] = int64(i + 1)
	}

	t.Run("rejected event", func(t *testing.T) {
		m := newEpsilonTestMonitor(t, failureSeedRule(values...), failureCheckRule())
		violation := wantViolation(t, m, eventTerm(failureSeedEvent, failureUnit()), eventTerm(failureCheckEvent, failureInt(0)))
		if got := len(violation.Failures.Final); got != len(values) {
			t.Fatalf("final records = %d, want all %d", got, len(values))
		}
		if len(violation.Failures.Earlier) != 0 {
			t.Fatalf("earlier records = %d, want none", len(violation.Failures.Earlier))
		}
	})

	t.Run("earlier event", func(t *testing.T) {
		m := newEpsilonTestMonitor(t, failureSeedRule(values...), failureCheckRule())
		violation := wantViolation(t, m,
			eventTerm(failureSeedEvent, failureUnit()), eventTerm(failureCheckEvent, failureInt(1)), eventTerm(failureStopEvent, failureUnit()))
		report := violation.Failures
		if len(report.Earlier) != FailureHistoryCap {
			t.Fatalf("earlier records = %d, want the cap %d", len(report.Earlier), FailureHistoryCap)
		}
		if report.Counts.Restriction != len(values)-1 {
			t.Fatalf("restriction count = %d, want %d", report.Counts.Restriction, len(values)-1)
		}
	})
}

func TestFailureRecordsCountEventsPerRun(t *testing.T) {
	m := failureTickMonitor(t)
	if violation := runFailureTrace(t, m,
		eventTerm(failureTickEvent, failureInt(1)),
		eventTerm(failureTickEvent, failureInt(2))); violation != nil {
		t.Fatalf("pre-trace violation: %+v", violation)
	}
	violation := wantViolation(t, m, eventTerm(failureStopEvent, failureUnit()))
	// The index counts the pre-trace, as the violation does.
	wantRecords(t, "final", violation.Failures.Final, core(3, "", FailureNoCandidate))
	wantRecords(t, "earlier", violation.Failures.Earlier,
		core(1, "FailureFail", FailureRestriction), core(2, "FailureFail", FailureRestriction))
	if violation.EventIndex != 3 {
		t.Fatalf("violation index = %d, want 3", violation.EventIndex)
	}
}

// TestFailureReportIsASnapshot checks that a report does not change when
// the monitor processes further events.
func TestFailureReportIsASnapshot(t *testing.T) {
	m := failureTickMonitor(t)
	processFailureEvent(t, m, eventTerm(failureTickEvent, failureInt(1)))
	report := m.failures.report()
	processFailureEvent(t, m, eventTerm(failureTickEvent, failureInt(2)))
	processFailureEvent(t, m, eventTerm(failureTickEvent, failureInt(3)))
	wantRecords(t, "final of the first report", report.Final, core(1, "FailureFail", FailureRestriction))
	if len(report.Earlier) != 0 || report.Counts != (FailureCounts{Restriction: 1}) {
		t.Fatalf("first report changed: %+v", report)
	}
}

// TestFailureRecordsAfterSeveralRewriteAlternatives checks the event
// indices of the core monitor after a raw event whose two rewrite
// alternatives both survive with different outputs.
func TestFailureRecordsAfterSeveralRewriteAlternatives(t *testing.T) {
	x := term.NewVariable("x")
	rewriter := newEpsilonTestMonitor(t,
		triggerRule("RewriteShort", nil, nil, outputActions(eventTerm("failureA", x)), eventTerm("failureRawFirst", x)),
		triggerRule("RewriteLong", nil, nil, outputActions(eventTerm("failureB", x), eventTerm("failureB2", x)), eventTerm("failureRawFirst", x)),
		triggerRule("RewriteLast", nil, nil, outputActions(eventTerm("failureC", x)), eventTerm("failureRawSecond", x)),
	)
	main := newEpsilonTestMonitor(t,
		triggerRule("MainA", nil, []*rule.Fact{linearFact("FailureSeenA")}, nil, eventTerm("failureA", x)),
		triggerRule("MainB", nil, []*rule.Fact{linearFact("FailureSeenB")}, nil, eventTerm("failureB", x)),
		triggerRule("MainB2", []*rule.Fact{linearFact("FailureSeenB")}, []*rule.Fact{linearFact("FailureSeenB")}, nil,
			eventTerm("failureB2", x)),
	)
	violation, err := runPipeline(t, rewriter, main, eventTerm("failureRawFirst", failureInt(1)), eventTerm("failureRawSecond", failureInt(2)))
	if err != nil || violation == nil {
		t.Fatalf("RunPipeline = (%+v, %v), want a violation of the core monitor", violation, err)
	}
	// The core monitor consumed a, b and b2 for the first raw event, so c
	// is its fourth event in both branches.
	if violation.EventIndex != 4 {
		t.Fatalf("violation event index = %d, want 4", violation.EventIndex)
	}
	want := core(4, "", FailureNoCandidate)
	want.rewrite = RewritePosition{RawEvent: 2, Alternative: 1, Position: 1}
	second := want
	second.rewrite.Alternative = 2
	wantRecords(t, "final", violation.Failures.Final, want, second)
	if violation.Failures.Final[0].Branch == violation.Failures.Final[1].Branch {
		t.Fatal("the two branches of the core monitor have the same hash")
	}
}

func TestFailureRecordsInPipeline(t *testing.T) {
	const (
		firstRaw  = "failureRawFirst"
		secondRaw = "failureRawSecond"
		unknown   = "failureRawUnknown"
		accepted  = "failureOutAccepted"
		follow    = "failureOutFollow"
		rejected  = "failureOutRejected"
	)
	x := term.NewVariable("x")
	// The first raw event is rewritten to one accepted event. The second
	// has two alternatives that fail at different positions, and a third
	// rewrite candidate whose restriction fails.
	rewriter := newEpsilonTestMonitor(t,
		triggerRule("RewriteFirst", nil, []*rule.Fact{linearFact("FailureRewritten", x)}, outputActions(eventTerm(accepted, x)), eventTerm(firstRaw, x)),
		triggerRule("RewriteShort", nil, nil, outputActions(eventTerm(accepted, x), eventTerm(rejected, x)), eventTerm(secondRaw, x)),
		triggerRule("RewriteLong", nil, nil, outputActions(eventTerm(accepted, x), eventTerm(follow, x), eventTerm(rejected, x)), eventTerm(secondRaw, x)),
		triggerRule("RewriteGuarded", nil, nil, append([]*rule.Fact{equalAction(x, failureInt(0))}, outputActions(eventTerm(accepted, x))...), eventTerm(secondRaw, x)),
	)
	main := newEpsilonTestMonitor(t,
		triggerRule("MainAccepted", nil, []*rule.Fact{linearFact("FailureAccepted", x)}, nil, eventTerm(accepted, x)),
		triggerRule("MainFollow", nil, []*rule.Fact{linearFact("FailureFollowed", x)}, nil, eventTerm(follow, x)),
	)
	initialCore := main.Configs()[0].Hash()

	violation, err := runPipeline(t, rewriter, main, eventTerm(firstRaw, failureInt(1)), eventTerm(secondRaw, failureInt(2)))
	if err != nil || violation == nil {
		t.Fatalf("RunPipeline = (%+v, %v), want a violation of the core monitor", violation, err)
	}
	// As before, the violation names the failure of the last alternative.
	if violation.EventIndex != 4 {
		t.Fatalf("violation event index = %d, want 4", violation.EventIndex)
	}
	rewrite := recordSummary{monitor: FailureMonitorRewrite, event: 2, rule: "RewriteGuarded", category: FailureRestriction}
	short := core(3, "", FailureNoCandidate)
	short.rewrite = RewritePosition{RawEvent: 2, Alternative: 1, Position: 2}
	long := core(4, "", FailureNoCandidate)
	long.rewrite = RewritePosition{RawEvent: 2, Alternative: 2, Position: 3}
	wantRecords(t, "final", violation.Failures.Final, rewrite, short, long)
	if len(violation.Failures.Earlier) != 0 {
		t.Fatalf("earlier records = %v, want none", summarize(violation.Failures.Earlier))
	}
	final := violation.Failures.Final
	// Each output is tried in the core configuration that the earlier
	// outputs of its alternative reached, which differ. The rewrite record
	// names the rewriter's configuration.
	branches := map[uint64]bool{initialCore: true}
	for _, record := range final {
		if record.Branch == 0 || branches[record.Branch] {
			t.Fatalf("branches = %x, %x, %x (initial core configuration %x), want distinct ones", final[0].Branch,
				final[1].Branch, final[2].Branch, initialCore)
		}
		branches[record.Branch] = true
	}

	t.Run("rewrite rejection", func(t *testing.T) {
		rewriter := newEpsilonTestMonitor(t,
			triggerRule("RewriteFirst", nil, nil, outputActions(eventTerm(accepted, x)), eventTerm(firstRaw, x)))
		main := newEpsilonTestMonitor(t, triggerRule("MainAccepted", nil, nil, nil, eventTerm(accepted, x)))
		event := eventTerm(unknown, failureInt(1))
		violation, err := runPipeline(t, rewriter, main, eventTerm(firstRaw, failureInt(1)), event)
		if violation != nil {
			t.Fatalf("violation = %+v, want the rewrite rejection as an error", violation)
		}
		if want := fmt.Sprintf("process event %s: rewrite violation: no applicable rule found", event); err == nil || err.Error() != want {
			t.Fatalf("error = %v, want %q", err, want)
		}
		if !errors.Is(err, ErrNoApplicableRule) {
			t.Fatalf("error %v is no rejection", err)
		}
		wantRecords(t, "final", main.FailureReport().Final,
			recordSummary{monitor: FailureMonitorRewrite, event: 2, category: FailureNoCandidate})
	})
}

// TestFailureReportOrderIsStable checks that the records of a rejection
// come in the order of their configuration hashes, in which the branches
// are tried, so that the order is the same in every run. In a pipeline,
// this holds for the branches that an earlier event derived as well.
func TestFailureReportOrderIsStable(t *testing.T) {
	t.Parallel()

	const branches = 8
	branchRules := func() []*rule.Rule {
		var rules []*rule.Rule
		for i := range branches {
			rules = append(rules, triggerRule(fmt.Sprintf("FailureOrderBranch%d", i), nil,
				[]*rule.Fact{linearFact("FailureOrderState", failureInt(int64(i)))}, nil, eventTerm(failureSeedEvent, failureUnit())))
		}
		return rules
	}
	wantHashOrder := func(t *testing.T, final []FailureRecord) {
		t.Helper()
		if len(final) != branches {
			t.Fatalf("records = %d, want one per branch", len(final))
		}
		for i := 1; i < len(final); i++ {
			if final[i-1].Branch >= final[i].Branch {
				t.Fatalf("records are not in the order of their branch hashes: %x before %x", final[i-1].Branch, final[i].Branch)
			}
		}
	}
	seed, stop := eventTerm(failureSeedEvent, failureUnit()), eventTerm(failureStopEvent, failureUnit())

	t.Run("monitor", func(t *testing.T) {
		t.Parallel()
		m := newEpsilonTestMonitor(t, branchRules()...)
		wantHashOrder(t, wantViolation(t, m, seed, stop).Failures.Final)
	})
	t.Run("pipeline", func(t *testing.T) {
		t.Parallel()
		rewriter := newEpsilonTestMonitor(t, branchRules()...)
		main := newEpsilonTestMonitor(t, triggerRule("FailureOrderMain", nil, nil, nil, seed))
		if _, err := runPipeline(t, rewriter, main, seed, stop); !errors.Is(err, ErrNoApplicableRule) {
			t.Fatalf("RunPipeline error = %v, want the rewrite rejection", err)
		}
		wantHashOrder(t, rewriter.FailureReport().Final)
	})
}
