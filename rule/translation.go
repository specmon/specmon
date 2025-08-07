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

// StartRule returns a new rule with the following properties:
//  1. The LHS contains all facts from the LHS of r.
//  2. The RHS contains a fact with all variables from the RHS of r
//     and pre-facts from function symbols of depth n.
func GenerateStartRule(r *Rule, D *TermNode) *Rule {
	ruleVars := nonPublicRuleVars(r)

	rhs := make([]*Fact, len(D.Leaves()))
	hints := make([]term.Term, len(D.Leaves()))
	for i, leaf := range D.Leaves() {
		f := term.Must(term.AsFunction(leaf.Value()))
		rhs[i] = NewFact(fmt.Sprintf("%s_%s_%s", SubtermName, r.Name, f.Name), []term.Term{
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
func GenerateEndRule(r *Rule, D *TermNode, U map[*TermNode]int, F *term.Binding) *Rule {
	ruleVars := term.AsTerms(utils.Unique(Facts(r.RHS).Vars()))

	lhs := make([]*Fact, D.Roots()[0].Children().Size())
	for i, d := range D.Roots()[0].Children().AsSlice() {
		f := term.Must(term.AsFunction(d.Value()))

		u := U[d]
		g := NewFact(fmt.Sprintf("%s_%s_%s", SubtermName, r.Name, nameForTerm(f)), []term.Term{
			term.NewFunction(term.PairFunctionName, ruleVars),
		}, LinearFact)

		if retVar := D.Label(d); retVar != nil {
			fVars := nonPublicRuleVars(r)

			// Find orignal function in F and add public variables to the fact.
			F.IterateSorted(func(k, v term.Term) bool {
				if v.Equal(retVar) {
					for _, vv := range term.Vars(k) {
						if vv.IsPublic() {
							fVars = append(fVars, vv)
						}
					}

					return false
				}

				return true
			})

			g.Args[0] = term.NewFunction(term.PairFunctionName, fVars)
			g.Args = append(g.Args, retVar)
		}

		if d.Parents().Size() > 1 {
			g.Name = fmt.Sprintf("%s_%s_%s_%d", SubtermName, r.Name, nameForTerm(f), u)
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

func LabelSubterms(n *TermNode, b *term.Binding) {
	for _, c := range n.Children().AsSlice() {
		ret := term.NewVariable(nameForTerm(c.Value()))

		n.AddChildrenWithLabel(ret, c)
		b.Set(c.Value(), ret)

		LabelSubterms(c, b)
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

	// Build a dependecny graph for the rule r.
	// Work on a copy of r do avoid modifying the original rule.
	D := BuildDAGForRule(r.Clone())

	// emove constants and varibles from D.
	RemoveConstants(D)
	RemoveVariables(D)

	// Label subterms with variables.
	F := term.NewBinding()
	LabelSubterms(D, F)

	// Keep mapping of subterms to variables prior to substitution.
	O := term.NewBinding()
	LabelSubterms(D, O)

	// Replace subterms with variables.
	ReplaceSubterms(D, F)

	// If the depth of the DAG is 0, we don't need to do anything.
	if D.Depth() == 0 {
		return []*Rule{r}
	}

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

		R := r.Clone()
		R.Attrs[TriggerAttributeName] = TermAttribute{triggers}

		return []*Rule{R}
	}

	// Add pre facts
	AddPreFacts(D)

	var R []*Rule
	U := make(map[*TermNode]int)

	// Generate rules for the DAG.
	R = append(R, GenerateStartRule(r, D))
	R = append(R, GenerateMidRules(r, D, U, O)...)
	R = append(R, GenerateEndRule(r, D, U, F))

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

func GenerateMidRules(r *Rule, D *TermNode, U map[*TermNode]int, F *term.Binding) []*Rule {
	var rules []*Rule

	ruleVarsNonPublic := nonPublicRuleVars(r)

	D.Traverse(data.TraverseDown, data.TraverseBFS, true, func(d *TermNode, w term.Term, _ int) bool {
		// Leave nodes are already handled by their parent nodes.
		if d.Value() == nil || d.Children().Empty() {
			return true
		}

		f := term.Must(term.AsFunction(d.Value()))

		// The facts in the RHS contain all non-public variables of the rule and the public variable of the function.
		fVars := ruleVarsNonPublic[:]

		F.IterateSorted(func(k, v term.Term) bool {
			if v.Equal(w) {
				for _, vv := range term.Vars(k) {
					if vv.IsPublic() {
						fVars = append(fVars, vv)
					}
				}

				return false
			}

			return true
		})

		// The RHS contains an instance of the function fact for each parent.
		rhs := make([]*Fact, d.Parents().Size())
		for i := range d.Parents().AsSlice() {
			var g *Fact
			if d.Parents().Size() > 1 {
				g = NewFact(fmt.Sprintf("%s_%s_%s_%d", SubtermName, r.Name, nameForTerm(f), i), []term.Term{
					// Include all variables of the rule in the fact.
					// Then, we don't have to add varsFacts for intermediate rules.
					term.NewFunction(term.PairFunctionName, fVars),
					term.NewFunction(f.Name, f.Args),
				}, LinearFact)
			} else {
				g = NewFact(fmt.Sprintf("%s_%s_%s", SubtermName, r.Name, nameForTerm(f)), []term.Term{
					// Include all variables of the rule in the fact.
					// Then, we don't have to add varsFacts for intermediate rules.
					term.NewFunction(term.PairFunctionName, fVars),
					term.NewFunction(f.Name, f.Args),
				}, LinearFact)
			}

			rhs[i] = g
		}

		lhs := make([]*Fact, d.Children().Size())
		for i, c := range d.Children().AsSlice() {
			f := term.Must(term.AsFunction(c.Value()))

			fVars := ruleVarsNonPublic[:]

			// If f is not a pre-fact, we add the public variables of f to the fact.
			// The reason for this is the following:
			// If f is not a pre-fact, than f as already been computed at this time.
			// Hence, the value fo the public variable as already been determined.
			// If however, it is a pre-fact, we first need to compute the value of the public variable
			// and can therefore not include it in the fact.
			if !strings.HasSuffix(f.Name, PreFactSuffix) {
				for _, v := range term.Vars(f) {
					if v.IsPublic() {
						fVars = append(fVars, v)
					}
				}
			}

			args := []term.Term{
				term.NewFunction(term.PairFunctionName, fVars),
			}

			if retVar := d.Label(c); retVar != nil {
				args = append(args, retVar)
			}

			// Pre-facts are already named based on their term
			// and can be used directly.
			fName := f.Name
			if !strings.HasSuffix(fName, PreFactSuffix) {
				fName = nameForTerm(f)
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
func AddPreFacts(D *TermNode) *TermNode {
	D.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, w term.Term, _ int) bool {
		// If the node is a leaf, we add a pre fact.
		// w != nil ensures that we don't run into an endless loop.
		if d.Children().Empty() && w != nil {
			f := term.Must(term.AsFunction(d.Value()))
			g := term.NewFunction(nameForTerm(f)+"_Pre", term.AsTerms(term.Terms(f.Args).Vars()))
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

// nameForTerm returns a string representation of a term.
// It is used to generate unique names for return values of functions.
func nameForTerm(t term.Term) string {
	switch t := t.(type) {
	case *term.Function:
		s := t.Name

		for _, a := range t.Args {
			s += nameForTerm(a)
		}

		return s
	case *term.Variable:
		return t.Name
	// Constants are handled by the default case.
	default:
		return strings.ReplaceAll(t.String(), "'", "")
	}
}

func nonPublicRuleVars(r *Rule) []term.Term {
	var nonPublicRuleVars []*term.Variable
	ruleVars := utils.Unique(Facts(r.LHS).Vars())

	for _, v := range ruleVars {
		if !v.IsPublic() {
			nonPublicRuleVars = append(nonPublicRuleVars, v)
		}
	}

	return term.AsTerms(nonPublicRuleVars)
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
