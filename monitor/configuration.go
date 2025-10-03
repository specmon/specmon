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

package monitor

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

const queueSize = 1

// Config is a configuration of the monitor.
type Config struct {
	// facts is a multiset of facts that are true in the current configuration.
	facts []*rule.Fact

	// seen is a multiset of events that have been seen in the current configuration
	// and that have not been processed yet.
	seen []term.Term

	// trace is a list of action facts that have been recorded in the current configuration.
	trace []*rule.Fact

	queue chan []*rule.Fact
}

// NewConfig returns a new configuration.
func NewConfig() *Config {
	return &Config{
		facts: []*rule.Fact{},
		seen:  []term.Term{},
		trace: []*rule.Fact{},
		queue: make(chan []*rule.Fact, queueSize),
	}
}

// Facts returns the facts of the configuration.
func (c *Config) Facts() []*rule.Fact {
	return c.facts
}

func (c *Config) DeleteFact(t *rule.Fact) bool {
	i := slices.IndexFunc(c.facts, func(s *rule.Fact) bool {
		return t.Equal(s)
	})

	if i == -1 {
		return false
	}

	c.facts = slices.Delete(c.facts, i, i+1)

	log.Tracef("removed %s\n", t)

	return true
}

func (c *Config) AddFact(t *rule.Fact) {
	c.facts = append(c.facts, t)
}

func (c *Config) Clone() *Config {
	d := NewConfig()
	d.facts = slices.Clone(c.facts)
	d.seen = slices.Clone(c.seen)
	d.trace = slices.Clone(c.trace)
	// c.queue cannot be cloned

	return d
}

func (c *Config) FactsAsSlice() []*rule.Fact {
	return c.facts
}

func (c *Config) FactsAsSliceWithName(name string) []*rule.Fact {
	var T []*rule.Fact
	for _, t := range c.facts {
		if t.Name == name {
			T = append(T, t)
		}
	}

	return T
}

func (c *Config) String() string {
	facts := make([]string, len(c.facts))
	for i := range c.facts {
		facts[i] = c.facts[i].String()
	}
	factsStr := strings.Join(facts, "\n")

	seen := make([]string, len(c.seen))
	for i := range c.seen {
		seen[i] = c.seen[i].String()
	}
	seenStr := strings.Join(seen, "\n")

	trace := make([]string, len(c.trace))
	for i := range c.trace {
		trace[i] = c.trace[i].String()
	}
	traceStr := strings.Join(trace, "\n")

	return fmt.Sprintf("{ [ %s ] | %s | %s }", factsStr, seenStr, traceStr)
}

func (c *Config) Hash() uint64 {
	h := fnv.New64a()

	for _, f := range c.facts {
		hash := f.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	for _, f := range c.trace {
		hash := f.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	for _, f := range c.seen {
		hash := f.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	return h.Sum64()
}

func (c *Config) AddSeen(t term.Term) {
	c.seen = append(c.seen, t)
}

func (c *Config) DeleteSeen(t term.Term) bool {
	i := slices.IndexFunc(c.seen, func(s term.Term) bool {
		return t.Equal(s)
	})

	if i == -1 {
		return false
	}

	c.seen = slices.Delete(c.seen, i, i+1)

	return true
}

// ApplyRule applies a rule to a configuration and returns the resulting configuration.
// If ev is a tuple of the form <fn, ret>, then fn is replaced by ret.
func (c *Config) ApplyRule(r *rule.Rule, b *term.Binding) (*Config, error) {
	log.Infof("   applying rule %s\n", r.Name)

	s := r.Subst(b)
	t := r.Subst(b)

	for _, f := range s.Triggers() {
		t = t.Subst(splitTupleBinding(f))
	}
	t = t.ReplaceFormats()

	if !t.IsGround() {
		return nil, fmt.Errorf("expected ground rule (%s), got variables: %v", t.Name, s.Vars())
	}

	d := c.Clone()

	// Delete the facts from the LHS.
	for _, f := range t.LHS {
		if f.IsLinear() && !d.DeleteFact(f) {
			return nil, fmt.Errorf("cannot delete non-existing fact '%s'", f)
		}
	}

	// Add the facts from the RHS.
	for _, f := range t.RHS {
		if !strings.HasSuffix(f.Name, "_") {
			d.AddFact(f)
		}
	}

	// Remove triggers from seen events.
	// Triggers in s still contain formats.
	for _, f := range s.Triggers() {
		if !d.DeleteSeen(term.ReplaceFormats(f)) {
			return nil, fmt.Errorf("cannot delete non-existing event '%s'", f)
		}
	}

	// Add action facts to trace.
	// FIXME: For performance reasons, this is commented out.
	// d.trace = append(d.trace, t.Act...)

	d.queue <- t.Act

	// Check if special event restrictions are satisfied.
	if err := restrSatisfied(t.Act); err != nil {
		return nil, fmt.Errorf("rule not applied: %w", err)
	}

	return d, nil
}

func splitTupleBinding(a term.Term) *term.Binding {
	b := term.NewBinding()

	fst, snd := splitPair(a)
	if fst == nil || snd == nil {
		return b
	}

	b.Set(fst, snd)

	return b
}

func splitPair(t term.Term) (term.Term, term.Term) {
	f, err := term.AsFunction(t)
	if err != nil || f == nil {
		return nil, nil
	}

	if f.Name != term.PairFunctionName || len(f.Args) != 2 {
		return nil, nil
	}

	fst := f.Args[0]
	snd := f.Args[1]

	return fst, snd
}

func restrSatisfied(trace []*rule.Fact) error {
	for _, t := range trace {
		switch t.Name {
		case RewriteEventName:
			// allowed event handled elsewhere
		case "Eq", "Equal":
			if len(t.Args) != 2 {
				return fmt.Errorf("event restriction: %s must have two arguments", t.Name)
			}
			if !t.Args[0].Equal(t.Args[1]) {
				return fmt.Errorf("event restriction violated: %s", t)
			}
		case "Neq", "NotEqual", "Unequal":
			if len(t.Args) != 2 {
				return fmt.Errorf("event restriction: %s must have two arguments", t.Name)
			}
			if t.Args[0].Equal(t.Args[1]) {
				return fmt.Errorf("event restriction violated: %s", t)
			}
		default:
			log.Warnf("ignoring action: %s", t)
		}
	}

	return nil
}
