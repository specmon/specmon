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

package rule

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/barkimedes/go-deepcopy"
	"github.com/specmon/specmon/term"
	"golang.org/x/exp/maps"
)

const (
	RoleWildcard = "*"
)

type Rule struct {
	Name  string               `json:"name"`
	LHS   []*Fact              `json:"lhs"`
	Act   []*Fact              `json:"act"`
	RHS   []*Fact              `json:"rhs"`
	Attrs map[string]Attribute `json:"attributes"`
}

func NewRule() *Rule {
	return &Rule{
		Name:  "",
		LHS:   make([]*Fact, 0),
		Act:   make([]*Fact, 0),
		RHS:   make([]*Fact, 0),
		Attrs: make(map[string]Attribute),
	}
}

func (r *Rule) String() string {
	var lhs, act, rhs, attrs string

	for _, l := range r.LHS {
		lhs += fmt.Sprintf("  , %s\n", l)
	}

	lhs = strings.TrimPrefix(strings.TrimSuffix(lhs, "\n"), "  , ")

	for _, a := range r.Act {
		act += fmt.Sprintf("  , %s\n", a)
	}
	act = strings.TrimPrefix(strings.TrimSuffix(act, "\n"), "  , ")

	for _, r := range r.RHS {
		rhs += fmt.Sprintf("  , %s\n", r)
	}
	rhs = strings.TrimPrefix(strings.TrimSuffix(rhs, "\n"), "  , ")

	if len(act) > 0 {
		act = fmt.Sprintf("\n--[ %s ]->\n", act)
	} else {
		act = "\n  -->\n"
	}

	// Ensure persistent order of attributes.
	attrKeys := maps.Keys(r.Attrs)
	sort.Strings(attrKeys)
	for _, k := range attrKeys {
		if k == TriggerAttributeName && !r.HasTriggers() {
			continue
		}
		if k == HintAttributeName && !r.HasHints() {
			continue
		}

		v := r.Attrs[k]
		if len(v.String()) > 0 {
			attrs += fmt.Sprintf("%s=%s, ", k, v)
		} else {
			attrs += k + ", "
		}
	}
	attrs = strings.TrimSuffix(attrs, ", ")

	if len(attrs) > 0 {
		attrs = fmt.Sprintf(" [ %s ]", attrs)
	}

	return fmt.Sprintf("rule %s%s:\n  [ %s ] %s  [ %s ]", r.Name, attrs, lhs, act, rhs)
}

func (r *Rule) Role() string {
	if attr, ok := r.Attrs[RoleAttributeName]; ok {
		return attr.GetString()
	}

	return ""
}

func (r *Rule) Triggers() []term.Term {
	if attr, ok := r.Attrs[TriggerAttributeName]; ok {
		return attr.GetTerms()
	}

	return nil
}

func (r *Rule) Hints() []term.Term {
	if attr, ok := r.Attrs[HintAttributeName]; ok {
		return attr.GetTerms()
	}

	return nil
}

func (r *Rule) NoDecomp() bool {
	_, ok := r.Attrs[NoDecompAttributeName]

	return ok
}

func (r *Rule) HasTriggers() bool {
	return len(r.Triggers()) > 0
}

func (r *Rule) HasHints() bool {
	return len(r.Hints()) > 0
}

func (r *Rule) Vars() []*term.Variable {
	var vars []*term.Variable

	for _, f := range r.LHS {
		vars = append(vars, f.Vars()...)
	}

	for _, f := range r.Act {
		vars = append(vars, f.Vars()...)
	}

	for _, f := range r.RHS {
		vars = append(vars, f.Vars()...)
	}

	return vars
}

// applyRule applies a rule to a configuration and returns the resulting configuration.
func (r *Rule) Subst(b *term.Binding) *Rule {
	s := &Rule{
		Name:  r.Name,
		LHS:   make([]*Fact, len(r.LHS)),
		Act:   make([]*Fact, len(r.Act)),
		RHS:   make([]*Fact, len(r.RHS)),
		Attrs: maps.Clone(r.Attrs),
	}

	for i := range r.LHS {
		s.LHS[i] = r.LHS[i].Subst(b)
	}

	for i := range r.Act {
		s.Act[i] = r.Act[i].Subst(b)
	}

	for i := range r.RHS {
		s.RHS[i] = r.RHS[i].Subst(b)
	}

	triggers := make([]term.Term, len(r.Triggers()))
	for i := range r.Triggers() {
		triggers[i] = r.Triggers()[i].Subst(b)
	}
	s.Attrs[TriggerAttributeName] = TermAttribute{triggers}

	hints := make([]term.Term, len(r.Hints()))
	for i := range r.Hints() {
		hints[i] = r.Hints()[i].Subst(b)
	}
	s.Attrs[HintAttributeName] = TermAttribute{hints}

	return s
}

func (r *Rule) IsGround() bool {
	for _, f := range r.LHS {
		if !f.IsGround() {
			return false
		}
	}

	for _, f := range r.Act {
		if !f.IsGround() {
			return false
		}
	}

	for _, f := range r.RHS {
		if !f.IsGround() {
			return false
		}
	}

	return true
}

func (r *Rule) Clone() *Rule {
	// deepcopy preserves the type.
	return deepcopy.MustAnything(r).(*Rule)
}

func SortRule(r *Rule) {
	sort.Sort(Facts(r.LHS))
	sort.Sort(Facts(r.Act))
	sort.Sort(Facts(r.RHS))
}

func ReadRules(filename string) []Rule {
	f, err := os.Open(filename)
	if err != nil {
		log.Panic(err.Error())
	}
	defer f.Close()

	log.Printf("Loading rules from %s\n", filename)
	bytes, err := io.ReadAll(f)
	if err != nil {
		log.Panic(err.Error())
	}

	var rules []Rule
	if err := json.Unmarshal(bytes, &rules); err != nil {
		log.Panic(err)
	}

	return rules
}

// ExpandFormats expands all format terms in a rule.
// Formats are not expanded in rule attributes.
func (r *Rule) ExpandFormats(b *term.Binding) *Rule {
	if b.Empty() {
		return r
	}

	s := &Rule{
		Name:  r.Name,
		LHS:   make([]*Fact, len(r.LHS)),
		Act:   make([]*Fact, len(r.Act)),
		RHS:   make([]*Fact, len(r.RHS)),
		Attrs: maps.Clone(r.Attrs),
	}

	s.LHS = Facts(r.LHS).ExpandFacts(b)
	s.Act = Facts(r.Act).ExpandFacts(b)
	s.RHS = Facts(r.RHS).ExpandFacts(b)

	return s
}

func (r *Rule) ReplaceFormats() *Rule {
	s := &Rule{
		Name:  r.Name,
		LHS:   make([]*Fact, len(r.LHS)),
		Act:   make([]*Fact, len(r.Act)),
		RHS:   make([]*Fact, len(r.RHS)),
		Attrs: maps.Clone(r.Attrs),
	}

	for i, f := range r.LHS {
		s.LHS[i] = f.ReplaceFormats()
	}

	for i, f := range r.Act {
		s.Act[i] = f.ReplaceFormats()
	}

	for i, f := range r.RHS {
		s.RHS[i] = f.ReplaceFormats()
	}

	triggers := make([]term.Term, len(r.Triggers()))
	for i, t := range r.Triggers() {
		triggers[i] = term.ReplaceFormats(t)
	}
	s.Attrs[TriggerAttributeName] = TermAttribute{triggers}

	hints := make([]term.Term, len(r.Hints()))
	for i, h := range r.Hints() {
		hints[i] = term.ReplaceFormats(h)
	}
	s.Attrs[HintAttributeName] = TermAttribute{hints}

	return s
}

type Rules []*Rule

func (r Rules) FilterByRole(role string) Rules {
	var rules Rules

	if role == "" || role == RoleWildcard {
		return r
	}

	for _, rule := range r {
		if rule.Role() == role || rule.Role() == RoleWildcard {
			rules = append(rules, rule)
		}
	}

	return rules
}

func (r Rules) FilterByDecomp() Rules {
	var rules Rules

	for _, rule := range r {
		if !rule.NoDecomp() {
			rules = append(rules, rule)
		}
	}

	return rules
}
