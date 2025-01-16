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
	"fmt"
	"strings"

	"github.com/specmon/specmon/term"
)

const (
	// NoDecompRuleAttribute is the attribute name for disabling decomposition of rules.
	NoDecompAttributeName = "no-decomp"

	// Role is the attribute name for the role of a rule.
	RoleAttributeName = "role"

	// Trigger is the attribute name for the trigger functions of a rule.
	TriggerAttributeName = "trigger"

	// Hint is the attribute name for the hint functions of a rule.
	HintAttributeName = "hint"
)

type Attribute interface {
	fmt.Stringer

	GetString() string
	GetTerms() []term.Term
}

type StringAttribute struct {
	Value string
}

func (s StringAttribute) String() string {
	return s.Value
}

func (s StringAttribute) GetString() string {
	return s.Value
}

func (s StringAttribute) GetTerms() []term.Term {
	return nil
}

type TermAttribute struct {
	Value []term.Term
}

func (t TermAttribute) String() string {
	s := make([]string, len(t.Value))
	for i, term := range t.Value {
		s[i] = term.String()
	}

	return fmt.Sprintf("[%s]", strings.Join(s, ", "))
}

func (t TermAttribute) GetString() string {
	return ""
}

func (t TermAttribute) GetTerms() []term.Term {
	return t.Value
}
