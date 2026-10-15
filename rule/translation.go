// Copyright (C) 2025-2026 CISPA Helmholtz Center for Information Security
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

package rule

import (
	"fmt"
	"sort"
	"strings"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/term"
	"github.com/specmon/specmon/utils"
)

const (
	StartRuleSuffix = "Start"
	EndRuleSuffix   = "End"

	SubtermName   = "ST"
	PreFactSuffix = "Pre"
	ComponentSep  = "_"

	SingleRuleDepth = 1
)

type TermNode = data.DAGNode[term.Term, term.Term]

func BuildDAGForRule(r *Rule) *TermNode {
	// Assumptions:
	// 1. LHS doesn't contain function symbols.
	// 2. LHS defines all variables in Act and RHS
	root := data.NewDAGNode[term.Term, term.Term](nil)

	combinedFacts := make([]*Fact, 0, len(r.RHS)+len(r.Act))
	combinedFacts = append(combinedFacts, r.RHS...)
	combinedFacts = append(combinedFacts, r.Act...)

	for _, fact := range combinedFacts {
		for _, arg := range fact.Args {
			argNode := FindTerm(root, arg)

			if argNode == nil {
				argNode = data.NewDAGNode[term.Term, term.Term](arg)
			}

			root.AddChildren(argNode)
			BuildDAG(argNode)
		}
	}

	return root
}

// GenerateStartRule returns a new rule with the following properties:
//  1. The LHS contains all facts from the LHS of r.
//  2. The RHS contains a pre-fact for each leaf of D, which carries
//     the premise variables of r.
func GenerateStartRule(r *Rule, D *TermNode, names *NameGenerator, original map[*TermNode]term.Term) *Rule {
	ruleVars := carriedVars(r, nil)

	rhs := make([]*Fact, len(D.Leaves()))
	hints := make([]term.Term, len(D.Leaves()))
	for i, leaf := range D.Leaves() {
		f := term.Must(term.AsFunction(leaf.Value()))
		termName := f.Name
		if !strings.HasSuffix(termName, PreFactSuffix) {
			termName = termNameForNode(names, original, leaf)
		}
		rhs[i] = NewFact(fmt.Sprintf("%s_%s_%s", SubtermName, r.Name, termName), []term.Term{
			term.NewFunction(term.PairFunctionName, ruleVars),
		},
			LinearFact,
		)

		// f is the pre fact added by AddPreFacts.
		// The function symbol of the pre fact is the parent of the leaf.
		// By construction their is exactly one.
		p := leaf.Parents().AsSlice()[0]
		g := term.Must(term.AsFunction(p.Value()))

		// The result variable of the function is the label of the leaf's parent.
		v := p.LabeldBy()[0]

		hints[i] = term.NewFunction(term.PairFunctionName, []term.Term{g, v})
	}

	endRule := &Rule{
		Name:  StartRuleSuffix,
		LHS:   r.LHS,
		Act:   []*Fact{},
		RHS:   rhs,
		Attrs: map[string]Attribute{},
	}

	endRule.Attrs[HintAttributeName] = TermAttribute{hints}

	return endRule
}

// GenerateEndRule returns a new rule with the following properties:
//
//	TODO
func GenerateEndRule(r *Rule, D *TermNode, U map[*TermNode]int, F *term.Binding, names *NameGenerator, original map[*TermNode]term.Term) *Rule {
	lhs := make([]*Fact, D.Children().Size())
	for i, d := range D.Children().AsSlice() {
		u := U[d]
		termName := termNameForNode(names, original, d)
		// LabelSubterms labels every child of the root.
		g := NewFact(fmt.Sprintf("%s_%s_%s", SubtermName, r.Name, termName), []term.Term{
			term.NewFunction(term.PairFunctionName, carriedVars(r, originalTerm(original, d))),
			D.Label(d),
		}, LinearFact)

		if d.Parents().Size() > 1 {
			g.Name = fmt.Sprintf("%s_%s_%s_%d", SubtermName, r.Name, termName, u)
		}

		lhs[i] = g
	}

	// Replace functions in r.RHS with variables.
	for i := range r.RHS {
		for j := range r.RHS[i].Args {
			r.RHS[i].Args[j] = term.FindReplaceBy(r.RHS[i].Args[j], func(t term.Term) bool {
				f, err := term.AsFunction(t)
				if err != nil {
					return false
				}

				_, ok := F.Get(f)

				return ok
			}, func(t term.Term) term.Term {
				f := term.Must(term.AsFunction(t))
				v, ok := F.Get(f)

				if ok {
					return v
				}

				return t
			})
		}
	}

	// Replace functions in r.Act with variables.
	for i := range r.Act {
		for j := range r.Act[i].Args {
			r.Act[i].Args[j] = term.FindReplaceBy(r.Act[i].Args[j], func(t term.Term) bool {
				f, err := term.AsFunction(t)
				if err != nil {
					return false
				}

				_, ok := F.Get(f)

				return ok
			}, func(t term.Term) term.Term {
				f := term.Must(term.AsFunction(t))
				v, ok := F.Get(f)

				if ok {
					return v
				}

				return t
			})
		}
	}

	return &Rule{
		Name:  EndRuleSuffix,
		LHS:   lhs,
		Act:   r.Act,
		RHS:   r.RHS,
		Attrs: r.Attrs,
	}
}

func BuildDAG(n *TermNode) {
	switch t := n.Value().(type) {
	case *term.Function:
		for _, arg := range t.Args {
			argNode := FindTerm(n, arg)

			if argNode == nil {
				argNode = data.NewDAGNode[term.Term, term.Term](arg)
			}

			if term.ReservedNames.Contains(t.Name) {
				for _, p := range n.Parents().AsSlice() {
					p.AddChildren(argNode)
				}
			} else {
				n.AddChildren(argNode)
			}
			BuildDAG(argNode)
		}
		if term.ReservedNames.Contains(t.Name) {
			n.Remove()
		}
	default:
	}
}

func LabelSubterms(n *TermNode, b *term.Binding, names *NameGenerator, original map[*TermNode]term.Term) {
	for _, c := range n.Children().AsSlice() {
		ret := term.NewVariable(names.NameForTerm(originalTerm(original, c)))

		n.AddChildrenWithLabel(ret, c)
		b.Set(originalTerm(original, c), ret)

		LabelSubterms(c, b, names, original)
	}
}

func ReplaceSubterms(n *TermNode, b *term.Binding) {
	n.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, _ term.Term, _ int) bool {
		if d == nil || d.Value() == nil {
			return true
		}

		d.SetValue(term.ReplaceBinding(d.Value(), b))

		return true
	})
}

func Translate(r *Rule /*, I data.Set[string]*/) []*Rule {
	combinedFacts := make([]*Fact, 0, len(r.RHS)+len(r.Act))
	combinedFacts = append(combinedFacts, r.RHS...)
	combinedFacts = append(combinedFacts, r.Act...)

	// If the RHS of r does not contain any functions, there is nothing to do.
	if !Facts(combinedFacts).HasFunctions() {
		return []*Rule{r}
	}

	// Build a dependency graph for the rule r.
	// Work on a copy of r to avoid modifying the original rule.
	D := BuildDAGForRule(r.Clone())

	// Remove constants and variables from D.
	RemoveConstants(D)
	RemoveVariables(D)

	// If the depth of the DAG is 0, no decomposition is needed.
	if D.Depth() == 0 {
		return []*Rule{r}
	}

	names := NewNameGenerator(r)

	// snapshotTerms captures the current Value() of each DAG node before
	// LabelSubterms/ReplaceSubterms mutate them. Pointer identity of
	// *TermNode keys is stable because DAG operations don't reallocate
	// existing nodes.
	original := snapshotTerms(D)

	// Label subterms with variables.
	F := term.NewBinding()
	LabelSubterms(D, F, names, original)

	// Replace subterms with variables.
	ReplaceSubterms(D, F)

	// If the depth of the DAG is 1, we only need to add
	// the required triggers.
	if D.Depth() == SingleRuleDepth {
		var triggers []term.Term
		for _, c := range D.Children().AsSlice() {
			f := term.Must(term.AsFunction(c.Value()))
			if w := D.Label(c); w != nil {
				triggers = append(triggers, term.NewFunction(term.PairFunctionName, []term.Term{f, w}))
			}
		}

		// Sort triggers so the output is deterministic regardless of
		// the order that RHS/Act facts were listed in the original rule.
		sort.Slice(triggers, func(i, j int) bool {
			return triggers[i].String() < triggers[j].String()
		})

		R := r.Clone()
		R.Attrs[TriggerAttributeName] = TermAttribute{triggers}

		return []*Rule{R}
	}

	// Add pre facts
	AddPreFacts(D, names, original)

	var R []*Rule
	U := make(map[*TermNode]int)

	// Generate rules for the DAG.
	R = append(R, GenerateStartRule(r, D, names, original))
	R = append(R, GenerateMidRules(r, D, U, names, original)...)
	R = append(R, GenerateEndRule(r, D, U, F, names, original))

	// Prefix generated rule names with the name of rule r.
	var count int
	for _, t := range R {
		if t.Name == "" {
			// For mid rules.
			t.Name = fmt.Sprintf("%s_%d", r.Name, count)
			count++
		} else {
			// For start and end rules.
			t.Name = fmt.Sprintf("%s_%s", r.Name, t.Name)
		}
		SortRule(t)
	}

	return R
}

func RemoveVariables(D *TermNode) *TermNode {
	D.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, _ term.Term, _ int) bool {
		if d.Value() != nil && d.Value().GetType() == term.VariableType {
			d.Remove()
		}

		return true
	})

	return D
}

func RemoveConstants(D *TermNode) *TermNode {
	D.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, _ term.Term, _ int) bool {
		if d.Value() != nil && d.Value().GetType() == term.ConstantType {
			d.Remove()
		}

		return true
	})

	return D
}

func GenerateMidRules(r *Rule, D *TermNode, U map[*TermNode]int, names *NameGenerator, original map[*TermNode]term.Term) []*Rule {
	var rules []*Rule

	D.Traverse(data.TraverseDown, data.TraverseBFS, true, func(d *TermNode, w term.Term, _ int) bool {
		// Leave nodes are already handled by their parent nodes.
		if d.Value() == nil || d.Children().Empty() {
			return true
		}

		f := term.Must(term.AsFunction(d.Value()))

		fVars := carriedVars(r, originalTerm(original, d))

		// The RHS contains an instance of the function fact for each parent.
		rhs := make([]*Fact, d.Parents().Size())
		for i := range d.Parents().AsSlice() {
			var g *Fact
			termName := termNameForNode(names, original, d)
			if d.Parents().Size() > 1 {
				g = NewFact(fmt.Sprintf("%s_%s_%s_%d", SubtermName, r.Name, termName, i), []term.Term{
					term.NewFunction(term.PairFunctionName, fVars),
					term.NewFunction(f.Name, f.Args),
				}, LinearFact)
			} else {
				g = NewFact(fmt.Sprintf("%s_%s_%s", SubtermName, r.Name, termName), []term.Term{
					term.NewFunction(term.PairFunctionName, fVars),
					term.NewFunction(f.Name, f.Args),
				}, LinearFact)
			}

			rhs[i] = g
		}

		lhs := make([]*Fact, d.Children().Size())
		for i, c := range d.Children().AsSlice() {
			f := term.Must(term.AsFunction(c.Value()))

			// A pre-fact is named after its term and precedes the
			// computation of the term, whose public variables are
			// therefore not bound yet.
			fName, fVars := f.Name, carriedVars(r, nil)
			if !strings.HasSuffix(f.Name, PreFactSuffix) {
				fName, fVars = termNameForNode(names, original, c), carriedVars(r, originalTerm(original, c))
			}

			args := []term.Term{
				term.NewFunction(term.PairFunctionName, fVars),
			}

			if retVar := d.Label(c); retVar != nil {
				args = append(args, retVar)
			}

			factName := fmt.Sprintf("%s_%s_%s", SubtermName, r.Name, fName)

			if c.Parents().Size() > 1 {
				i := U[c]
				factName = fmt.Sprintf("%s_%s_%s_%d", SubtermName, r.Name, fName, i)
				U[c]++
			}

			lhs[i] = NewFact(factName, args, LinearFact)
		}

		R := &Rule{
			Name:  "",
			LHS:   lhs,
			Act:   []*Fact{},
			RHS:   rhs,
			Attrs: make(map[string]Attribute),
		}

		var triggers []term.Term
		if w != nil {
			triggers = []term.Term{term.NewFunction(term.PairFunctionName, []term.Term{f, w})}
		}

		R.Attrs[TriggerAttributeName] = TermAttribute{triggers}

		rules = append(rules, R)

		return true
	})

	return rules
}

// AddPreFacts adds Pre facts for all leave nodes that are observable.
func AddPreFacts(D *TermNode, names *NameGenerator, original map[*TermNode]term.Term) *TermNode {
	D.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, w term.Term, _ int) bool {
		// If the node is a leaf, we add a pre fact.
		// w != nil ensures that we don't run into an endless loop.
		if d.Children().Empty() && w != nil {
			f := term.Must(term.AsFunction(d.Value()))
			name := names.NameForTerm(originalTerm(original, d))
			g := term.NewFunction(name+"_Pre", term.AsTerms(term.Terms(f.Args).Vars()))
			d.AddChildren(data.NewDAGNode[term.Term, term.Term](g))
		}

		return true
	})

	return D
}

func FindTerm(n *TermNode, arg term.Term) *TermNode {
	return n.FindFunc(func(d *TermNode) bool {
		return arg.Equal(d.Value())
	})
}

func snapshotTerms(D *TermNode) map[*TermNode]term.Term {
	original := make(map[*TermNode]term.Term)
	D.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, _ term.Term, _ int) bool {
		if d != nil && d.Value() != nil {
			original[d] = d.Value()
		}
		return true
	})
	return original
}

func originalTerm(original map[*TermNode]term.Term, node *TermNode) term.Term {
	if node == nil {
		return nil
	}
	if t, ok := original[node]; ok {
		return t
	}
	return node.Value()
}

func termNameForNode(names *NameGenerator, original map[*TermNode]term.Term, node *TermNode) string {
	if names == nil {
		return ""
	}
	t := originalTerm(original, node)
	if t == nil {
		return ""
	}
	return names.NameForTerm(t)
}

// carriedVars returns the variables that the ST_ fact of a DAG node carries
// through the chain of split rules: the non-public premise variables, then
// the public premise variables, then the public variables of the node's
// original term t, without duplicates. Every producer and consumer of a
// fact computes its tuple here, so the chain stays consistent. A public
// variable of t is carried from the observation of the computation that
// binds it, including one nested in a subterm. Pass a nil t for a pre-fact:
// the variables of its term are not bound yet.
func carriedVars(r *Rule, t term.Term) []term.Term {
	var nonPublic, public []*term.Variable
	for _, v := range Facts(r.LHS).Vars() {
		if v.IsPublic() {
			public = append(public, v)
		} else {
			nonPublic = append(nonPublic, v)
		}
	}
	for _, v := range term.Vars(t) {
		if v.IsPublic() {
			public = append(public, v)
		}
	}
	return term.AsTerms(utils.Unique(append(nonPublic, public...)))
}

// FIXME: Find a place for this function.
// IsStartRuleOf returns true if r1 is the start rule of r2.
func IsStartRuleOf(r1, r2 *Rule) bool {
	// If r1 is not a start rule or r2 is an end rule, return false.
	if !strings.HasSuffix(r1.Name, ComponentSep+StartRuleSuffix) ||
		strings.HasSuffix(r2.Name, ComponentSep+EndRuleSuffix) {
		return false
	}

	ruleName := strings.TrimSuffix(r1.Name, StartRuleSuffix)

	return strings.HasPrefix(r2.Name, ruleName)
}

// MatchesSplitStateName recognizes the end-rule and split-state naming
// relation. This is not provenance: prefix-related source names can
// overlap, for example R_End and a state named ST_R_g_y_0.
func (r *Rule) MatchesSplitStateName(f *Fact) bool {
	source, end := strings.CutSuffix(r.Name, ComponentSep+EndRuleSuffix)
	return end && strings.HasPrefix(f.Name, SubtermName+ComponentSep+source+ComponentSep)
}
