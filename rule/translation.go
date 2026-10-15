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
	"slices"
	"sort"
	"strconv"
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

// translationCtx holds the state shared by the steps of one translation.
type translationCtx struct {
	rule        *Rule                   // the source rule, never mutated
	dag         *TermNode               // root of the rule's DAG
	names       *NameGenerator          // deterministic name generator
	original    map[*TermNode]term.Term // node terms before labeling
	funcBinding *term.Binding           // original function to its label variable
	parentCount map[*TermNode]int       // next index of a node with several parents
}

// stFactName builds the standardized ST fact name for a decomposed rule.
func stFactName(ruleName, termName string) string {
	return fmt.Sprintf("%s_%s_%s", SubtermName, ruleName, termName)
}

// replaceFunctionsWithVars clones the given facts and replaces all function
// subterms that appear in the binding with their corresponding variables.
func replaceFunctionsWithVars(facts []*Fact, binding *term.Binding) []*Fact {
	cloned := make([]*Fact, len(facts))
	for i, f := range facts {
		args := make([]term.Term, len(f.Args))
		for j, arg := range f.Args {
			args[j] = term.FindReplaceBy(arg, func(t term.Term) bool {
				_, ok := binding.Get(t)
				return ok
			}, func(t term.Term) term.Term {
				v, _ := binding.Get(t)
				return v
			})
		}
		cloned[i] = NewFact(f.Name, args, f.Type)
	}
	return cloned
}

// buildMidRuleLHS constructs the facts that the rule of DAG node d
// consumes, one for each child of d.
func buildMidRuleLHS(ctx *translationCtx, d *TermNode) []*Fact {
	lhs := make([]*Fact, d.Children().Size())
	for i, c := range d.Children().AsSlice() {
		// A pre-fact, the only child reached by an edge without a label,
		// precedes the computation of its term, whose public variables are
		// therefore not bound yet. Its name is already based on its term.
		name := term.Must(term.AsFunction(c.Value())).Name
		args := []term.Term{term.NewFunction(term.PairFunctionName, carriedVars(ctx.rule, nil))}
		if w := d.Label(c); w != nil {
			orig := originalTerm(ctx.original, c)
			name = ctx.names.NameForTerm(orig)
			args = []term.Term{term.NewFunction(term.PairFunctionName, carriedVars(ctx.rule, orig)), w}
		}

		factName := stFactName(ctx.rule.Name, name)
		if c.Parents().Size() > 1 {
			args = append(args, term.NewConstant(int64(ctx.parentCount[c])))
			ctx.parentCount[c]++
		}

		lhs[i] = NewFact(factName, args, LinearFact)
	}
	return lhs
}

// buildMidRuleRHS constructs the RHS facts for a mid rule at DAG node d.
func buildMidRuleRHS(ctx *translationCtx, d *TermNode) []*Fact {
	f := term.Must(term.AsFunction(d.Value()))
	orig := originalTerm(ctx.original, d)
	termName := ctx.names.NameForTerm(orig)
	fVars := carriedVars(ctx.rule, orig)

	rhs := make([]*Fact, d.Parents().Size())
	for i := range d.Parents().AsSlice() {
		args := []term.Term{
			term.NewFunction(term.PairFunctionName, fVars),
			term.NewFunction(f.Name, f.Args),
		}
		if d.Parents().Size() > 1 {
			args = append(args, term.NewConstant(int64(i)))
		}
		rhs[i] = NewFact(stFactName(ctx.rule.Name, termName), args, LinearFact)
	}
	return rhs
}

// computationRule returns the rule that computes the term of DAG node d,
// whose result is the label w, from the facts lhs.
func computationRule(ctx *translationCtx, d *TermNode, w term.Term, lhs []*Fact) *Rule {
	return &Rule{
		LHS:   lhs,
		Act:   []*Fact{},
		RHS:   buildMidRuleRHS(ctx, d),
		Attrs: map[string]Attribute{TriggerAttributeName: TermAttribute{computation(d, w)}},
	}
}

// computation returns the trigger or hint term for the computation of the
// term of DAG node d, whose result is the label w.
func computation(d *TermNode, w term.Term) []term.Term {
	return []term.Term{term.NewFunction(term.PairFunctionName, []term.Term{d.Value(), w})}
}

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

// generateStartRule returns a start rule with hints for each leaf function.
func generateStartRule(ctx *translationCtx) *Rule {
	// Every leaf is a pre-fact, and its parent is the function to compute.
	leaves := ctx.dag.Leaves()
	rhs := make([]*Fact, len(leaves))
	var hints []term.Term
	for i, leaf := range leaves {
		f := term.Must(term.AsFunction(leaf.Value()))
		rhs[i] = NewFact(stFactName(ctx.rule.Name, f.Name), []term.Term{
			term.NewFunction(term.PairFunctionName, carriedVars(ctx.rule, nil)),
		}, LinearFact)

		p := leaf.Parents().AsSlice()[0]
		hints = append(hints, computation(p, p.LabeldBy()[0])...)
	}

	return &Rule{
		Name:  StartRuleSuffix,
		LHS:   slices.Clone(ctx.rule.LHS),
		Act:   []*Fact{},
		RHS:   rhs,
		Attrs: map[string]Attribute{HintAttributeName: TermAttribute{hints}},
	}
}

// generateEndRule returns the end rule, which rebuilds the conclusions and
// actions of the source rule from the facts of the root's children. If
// fused is not nil, it is the single child of the root, whose rule is
// merged into the end rule: the end rule consumes the facts of its children
// and is triggered by its computation instead of being an epsilon rule.
func generateEndRule(ctx *translationCtx, fused *TermNode) *Rule {
	end := ctx.rule.Clone()
	end.Name = EndRuleSuffix
	end.RHS = replaceFunctionsWithVars(ctx.rule.RHS, ctx.funcBinding)
	end.Act = replaceFunctionsWithVars(ctx.rule.Act, ctx.funcBinding)
	if fused == nil {
		end.LHS = buildMidRuleLHS(ctx, ctx.dag)
	} else {
		end.LHS = buildMidRuleLHS(ctx, fused)
		end.Attrs[TriggerAttributeName] = TermAttribute{computation(fused, ctx.dag.Label(fused))}
	}
	return end
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

// Translate decomposes eligible rules in order and rejects generated fact names
// shared by differently named source rules. Rules with no-decomp, hints or
// triggers pass through unchanged. Only names absent from their source rule's
// facts count as generated.
func (rules Rules) Translate() (Rules, error) {
	var translatedRules Rules
	generatedBy := make(map[string]string)
	for _, r := range rules {
		if !r.NoDecomp() && !r.HasHints() && !r.HasTriggers() {
			translated := Translate(r)
			sourceNames := make(map[string]bool)
			for _, fact := range slices.Concat(r.LHS, r.Act, r.RHS) {
				sourceNames[fact.Name] = true
			}
			for _, split := range translated {
				for _, fact := range slices.Concat(split.LHS, split.Act, split.RHS) {
					if sourceNames[fact.Name] {
						continue
					}
					if owner, found := generatedBy[fact.Name]; found && owner != r.Name {
						return nil, fmt.Errorf("rules %s and %s both generate the fact %s, so one of them must be renamed", owner, r.Name, fact.Name)
					}
					generatedBy[fact.Name] = r.Name
				}
			}
			translatedRules = append(translatedRules, translated...)
		} else {
			translatedRules = append(translatedRules, r)
		}
	}

	return translatedRules, nil
}

func Translate(r *Rule) []*Rule {
	combinedFacts := make([]*Fact, 0, len(r.RHS)+len(r.Act))
	combinedFacts = append(combinedFacts, r.RHS...)
	combinedFacts = append(combinedFacts, r.Act...)

	// If the RHS of r does not contain any functions, there is nothing to do.
	if !Facts(combinedFacts).HasFunctions() {
		return []*Rule{r}
	}

	// Build a dependency graph for the rule r.
	// Work on a copy of r to avoid modifying the original rule.
	dag := BuildDAGForRule(r.Clone())

	// Remove constants and variables from the DAG.
	removeConstants(dag)
	removeVariables(dag)

	// Labeling and replacing subterms keep the topology, so the depth
	// computed here stays valid.
	depth := dag.Depth()

	// If the depth of the DAG is 0, no decomposition is needed.
	if depth == 0 {
		return []*Rule{r}
	}

	names := NewNameGenerator(r)

	// snapshotTerms captures the current Value() of each DAG node before
	// LabelSubterms/ReplaceSubterms mutate them. Pointer identity of
	// *TermNode keys is stable because DAG operations don't reallocate
	// existing nodes.
	original := snapshotTerms(dag)

	// Label subterms with variables.
	funcBinding := term.NewBinding()
	LabelSubterms(dag, funcBinding, names, original)

	// Replace subterms with variables.
	ReplaceSubterms(dag, funcBinding)

	// If the depth of the DAG is 1, we only need to add the required triggers.
	if depth == SingleRuleDepth {
		var triggers []term.Term
		for _, c := range dag.Children().AsSlice() {
			triggers = append(triggers, computation(c, dag.Label(c))...)
		}

		// Sort triggers for deterministic output.
		sort.Slice(triggers, func(i, j int) bool {
			return triggers[i].String() < triggers[j].String()
		})

		R := r.Clone()
		R.Attrs[TriggerAttributeName] = TermAttribute{triggers}

		return []*Rule{R}
	}

	ctx := &translationCtx{
		rule:        r,
		dag:         dag,
		names:       names,
		original:    original,
		funcBinding: funcBinding,
		parentCount: make(map[*TermNode]int),
	}

	var rules []*Rule
	if leaves := dag.Leaves(); len(leaves) == 1 && len(r.LHS) > 0 {
		// With a single leaf there is nothing to look ahead for, so the
		// start rule is fused with the leaf's rule: it matches the
		// premises of r and is triggered by the leaf computation. No
		// pre-facts are needed. A rule without premises keeps its start
		// rule, a hint rule that loading rejects, whatever the number of
		// its innermost computations.
		rules = append(rules, computationRule(ctx, leaves[0], leaves[0].LabeldBy()[0], slices.Clone(r.LHS)))
	} else {
		addPreFacts(dag, names, original)
		rules = append(rules, generateStartRule(ctx))
	}

	// With a single root child, the rule of that child is fused with the
	// end rule, which is then triggered by the child's computation
	// instead of being an epsilon rule.
	var fused *TermNode
	if dag.Children().Size() == 1 {
		fused = dag.Children().AsSlice()[0]
	}

	rules = append(rules, generateMidRules(ctx, fused)...)
	rules = append(rules, generateEndRule(ctx, fused))

	// Prefix generated rule names with the name of rule r.
	var count int
	for _, t := range rules {
		if t.Name == "" {
			t.Name = fmt.Sprintf("%s_%d", r.Name, count)
			count++
		} else {
			t.Name = fmt.Sprintf("%s_%s", r.Name, t.Name)
		}
		SortRule(t)
	}

	return rules
}

// removeVariables removes all variable nodes from the DAG in place.
func removeVariables(dag *TermNode) {
	dag.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, _ term.Term, _ int) bool {
		if d.Value() != nil && d.Value().GetType() == term.VariableType {
			d.Remove()
		}
		return true
	})
}

// removeConstants removes all constant nodes from the DAG in place.
func removeConstants(dag *TermNode) {
	dag.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, _ term.Term, _ int) bool {
		if d.Value() != nil && d.Value().GetType() == term.ConstantType {
			d.Remove()
		}
		return true
	})
}

// generateMidRules produces intermediate trigger rules for the DAG.
// No rule is generated for fused, which is merged into the end rule.
func generateMidRules(ctx *translationCtx, fused *TermNode) []*Rule {
	var rules []*Rule
	ctx.dag.Traverse(data.TraverseDown, data.TraverseBFS, true, func(d *TermNode, w term.Term, _ int) bool {
		// Leaf nodes are handled by their parent nodes.
		if d.Value() != nil && !d.Children().Empty() && d != fused {
			rules = append(rules, computationRule(ctx, d, w, buildMidRuleLHS(ctx, d)))
		}
		return true
	})
	return rules
}

// addPreFacts adds Pre facts for all leaf nodes that are observable.
// It mutates the DAG in place.
func addPreFacts(dag *TermNode, names *NameGenerator, original map[*TermNode]term.Term) {
	dag.Traverse(data.TraverseDown, data.TraverseDFS, true, func(d *TermNode, w term.Term, _ int) bool {
		// If the node is a leaf, we add a pre fact.
		// w != nil ensures that we don't run into an endless loop.
		if d.Children().Empty() && w != nil {
			f := term.Must(term.AsFunction(d.Value()))
			name := names.NameForTerm(originalTerm(original, d))
			g := term.NewFunction(name+ComponentSep+PreFactSuffix, term.AsTerms(term.Terms(f.Args).Vars()))
			d.AddChildren(data.NewDAGNode[term.Term, term.Term](g))
		}
		return true
	})
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

// IsStartRuleOf returns true if r1 is the start rule of the source rule
// that r2 was generated from. Generated rules are named after their source
// rule, followed by the start or end suffix or by a step number in decimal
// without leading zeros.
func IsStartRuleOf(r1, r2 *Rule) bool {
	source, ok := strings.CutSuffix(r1.Name, ComponentSep+StartRuleSuffix)
	if !ok {
		return false
	}
	suffix, ok := strings.CutPrefix(r2.Name, source+ComponentSep)
	if !ok {
		return false
	}
	if suffix == StartRuleSuffix || suffix == EndRuleSuffix {
		return true
	}
	number, err := strconv.ParseUint(suffix, 10, 0)
	return err == nil && strconv.FormatUint(number, 10) == suffix
}

// MatchesSplitStateName recognizes the end-rule and split-state naming
// relation. This is not provenance: prefix-related source names can
// overlap, for example R_End and a state named ST_R_g_y_0.
func (r *Rule) MatchesSplitStateName(f *Fact) bool {
	source, end := strings.CutSuffix(r.Name, ComponentSep+EndRuleSuffix)
	return end && strings.HasPrefix(f.Name, SubtermName+ComponentSep+source+ComponentSep)
}
