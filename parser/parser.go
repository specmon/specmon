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
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	spthy "github.com/specmon/specmon/parser/tree-sitter-spthy"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
	"github.com/specmon/specmon/utils"
)

const (
	errorContextBeforeOffset = 2
	errorContextAfterOffset  = 2

	rulePattern = `
    (simple_rule
      (ident) @rule.name
	  (rule_attrs (_))? @rule.attrs
	  (rule_let_block (_))? @rule.let_block
      (premise 
        [(linear_fact) (persistent_fact)]*) @rule.LHS
      (action_fact
        [(linear_fact) (persistent_fact)]*)? @rule.Act
      (conclusion
        [(linear_fact) (persistent_fact)]*) @rule.RHS)`

	factPattern = `
    [(linear_fact
       fact_identifier: (fact_identifier) @fact.name
       (arguments argument: (_))* @fact.arguments)
     (persistent_fact
       fact_identifier: (fact_identifier) @fact.name
       (arguments argument: (_))* @fact.arguments)] @fact`

	macroPattern = `
	(macro
		left: (_) @macro.left
		right: (_) @macro.right)`

	errorPattern = `(ERROR) @error`
)

type Parser struct {
	srcFile string
	src     []byte
	lang    *sitter.Language
}

func NewParser(filename string, src []byte, lang *sitter.Language) *Parser {
	return &Parser{
		srcFile: filepath.Clean(filename),
		src:     src,
		lang:    lang,
	}
}

type ParseError struct {
	parser *Parser
	err    error
}

func (e *ParseError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}

	return fmt.Sprintf("cannot parse '%s'", e.parser.srcFile)
}

func (e *ParseError) Unwrap() error {
	return e.err
}

func childrenByFieldName(node *sitter.Node, fieldName string) []*sitter.Node {
	var results []*sitter.Node

	cursor := node.Walk()
	defer cursor.Close()

	if !cursor.GotoFirstChild() {
		return results
	}

	for {
		if cursor.FieldName() == fieldName {
			results = append(results, cursor.Node())
		}
		if !cursor.GotoNextSibling() {
			break
		}
	}

	return results
}

func getCaptureMap(q *sitter.Query, m *sitter.QueryMatch) map[string]*sitter.Node {
	captures := make(map[string]*sitter.Node)
	captureNames := q.CaptureNames()
	for _, c := range m.Captures {
		index := int(c.Index)
		if index >= len(captureNames) {
			continue
		}
		node := c.Node
		captures[captureNames[index]] = &node
	}

	return captures
}

func (p *Parser) errorNodeToError(node *sitter.Node) error {
	if !node.HasError() {
		return nil
	}

	// TODO: node.HasError also returns true if a subnode is missing or extra.
	// In this case, the error pattern failes to match.
	query, err := sitter.NewQuery(p.lang, errorPattern)
	if err != nil {
		return &ParseError{p, err}
	}
	defer query.Close()

	queryCursor := sitter.NewQueryCursor()
	defer queryCursor.Close()

	matches := queryCursor.Matches(query, node, p.src)
	m := matches.Next()
	if m == nil {
		return &ParseError{p, errors.New("cannot match error pattern")}
	}

	captures := getCaptureMap(query, m)
	if errorNode, ok := captures["error"]; ok {
		start := errorNode.StartPosition()
		errorLine := start.Row + 1
		errorColumn := start.Column + 1

		srcLines := strings.Split(string(p.src), "\n")

		beforeContextLine := max(0, int(errorLine)-errorContextBeforeOffset-1)         //nolint:gosec
		afterContextLine := min(len(srcLines), int(errorLine)+errorContextAfterOffset) //nolint:gosec

		errorContext := srcLines[beforeContextLine:afterContextLine]

		return &ParseError{p, fmt.Errorf("%s:%d:%d: syntax error \n\n%s",
			p.srcFile, errorLine, errorColumn,
			utils.Indent(utils.NumberLines(strings.Join(errorContext, "\n"), beforeContextLine), 2))}
	}

	return &ParseError{p, errors.New("cannot get error node")}
}

func (p *Parser) parseTerm(c *sitter.Node) term.Term {
	switch c.Kind() {
	case "msg_var_or_nullary_fun", "pub_var", "fresh_var":
		ident := c.ChildByFieldName("variable_identifier")
		if ident != nil {
			v := ident.Utf8Text(p.src)
			if c.Kind() == "pub_var" {
				v = term.PublicPrefix + v
			}

			return term.NewVariable(v)
		}
	case "nat_var":
		// The parser doesn't distinguish between a constant number literal
		// and a variable. Hence, we need to try to parse the number as an interger.
		ident := c.ChildByFieldName("variable_identifier")
		if i, err := strconv.Atoi(ident.Utf8Text(p.src)); err == nil {
			return term.NewConstant[int](i)
		}

		return term.NewVariable(ident.Utf8Text(p.src))
	case "pub_name":
		return p.parsePubName(c)
	case "nary_app", "nullary_fun":
		ident := c.ChildByFieldName("function_identifier")
		args := []term.Term{}
		if ident != nil {
			for i := uint(0); i < c.ChildCount(); i++ {
				child := c.Child(i)
				if child.Kind() == "arguments" {
					arguments := childrenByFieldName(child, "argument")
					for _, arg := range arguments {
						args = append(args, p.parseTerm(arg))
					}
				}
			}

			return term.NewFunction(ident.Utf8Text(p.src), args)
		}
	case "tuple_term":
		termNodes := childrenByFieldName(c, "term")
		terms := make([]term.Term, len(termNodes))
		for i := range termNodes {
			terms[i] = p.parseTerm(termNodes[i])
		}

		return term.NewFunction(term.PairFunctionName, terms)
	case "exp_term":
		return term.NewFunction(term.ExpFunctionName, []term.Term{
			p.parseTerm(c.Child(0)),
			p.parseTerm(c.Child(2)),
		})
	case "nat_term":
		return term.NewFunction(term.AddFunctionName, []term.Term{
			p.parseTerm(c.Child(0)),
			p.parseTerm(c.Child(2)),
		})
	default:
		traverse(c, 0)
		panic(fmt.Sprintf("unhandled term type: %s (%s)", c.Kind(), c.Utf8Text(p.src)))
	}

	return nil
}

func (p *Parser) parseFacts(node *sitter.Node, factQuery *sitter.Query, factQueryCursor *sitter.QueryCursor) []*rule.Fact {
	var facts []*rule.Fact

	matches := factQueryCursor.Matches(factQuery, node, p.src)
	for m := matches.Next(); m != nil; m = matches.Next() {
		captures := getCaptureMap(factQuery, m)

		args := []term.Term{}
		if captures["fact.arguments"] != nil {
			for i := uint(0); i < captures["fact.arguments"].ChildCount(); i++ {
				c := captures["fact.arguments"].Child(i)
				if c.IsNamed() {
					args = append(args, p.parseTerm(c))
				}
			}
		}

		var factType rule.FactType
		switch captures["fact"].Kind() {
		case "linear_fact":
			factType = rule.LinearFact
		case "persistent_fact":
			factType = rule.PersistentFact
		}

		fact := rule.NewFact(captures["fact.name"].Utf8Text(p.src), args, factType)

		facts = append(facts, fact)
	}

	return facts
}

// ParseFile reads the given file, preprocesses it with the given defines,
// and parses the rules from it.
func ParseFile(ctx context.Context, filename string, defines []string) ([]*rule.Rule, error) {
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, &ParseError{NewParser(filename, nil, nil), err}
	}

	// First parse for preprocessing
	initialTree, err := Parse(ctx, src)
	if err != nil {
		// Create a parser instance for error reporting
		p := NewParser(filename, src, spthy.GetLanguage())
		return nil, &ParseError{p, err}
	}

	// Preprocess the source code
	preprocessor := NewPreprocessor(src, defines)
	preprocessedSrc := preprocessor.Run(initialTree.RootNode())

	// Now, parse the preprocessed source to get the final AST
	return parseRules(ctx, filename, preprocessedSrc)
}

func parseRules(ctx context.Context, filename string, src []byte) ([]*rule.Rule, error) {
	p := NewParser(filename, src, spthy.GetLanguage())

	sitterParser := sitter.NewParser()
	defer sitterParser.Close()
	if err := sitterParser.SetLanguage(p.lang); err != nil {
		return nil, &ParseError{p, err}
	}

	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, &ParseError{p, ctx.Err()}
		default:
		}
	}

	tree := sitterParser.Parse(src, nil)
	if tree == nil {
		return nil, &ParseError{p, errors.New("failed to parse source")}
	}

	rootNode := tree.RootNode()
	// traverse(rootNode, 0)
	if err := p.errorNodeToError(rootNode); err != nil {
		return nil, &ParseError{p, err}
	}

	ruleQuery, err := sitter.NewQuery(spthy.GetLanguage(), rulePattern)
	if err != nil {
		return nil, &ParseError{p, err}
	}
	defer ruleQuery.Close()

	factQuery, err := sitter.NewQuery(spthy.GetLanguage(), factPattern)
	if err != nil {
		return nil, &ParseError{p, err}
	}
	defer factQuery.Close()

	ruleQueryCursor := sitter.NewQueryCursor()
	defer ruleQueryCursor.Close()

	factQueryCursor := sitter.NewQueryCursor()
	defer factQueryCursor.Close()

	// formats := filterFormatMacros(p.parseMacros(rootNode))
	formats := p.parseMacros(rootNode)

	var rules []*rule.Rule
	ruleMatches := ruleQueryCursor.Matches(ruleQuery, rootNode, src)
	for m := ruleMatches.Next(); m != nil; m = ruleMatches.Next() {
		b := term.NewBinding()

		captureMap := getCaptureMap(ruleQuery, m)

		r := rule.NewRule()
		if node := captureMap["rule.name"]; node != nil {
			r.Name = node.Utf8Text(src)
		}
		if node := captureMap["rule.attrs"]; node != nil {
			r.Attrs = p.parseRuleAttributes(node)
		}
		if node := captureMap["rule.let_block"]; node != nil {
			b = p.parseLetBlock(node)
		}
		if node := captureMap["rule.LHS"]; node != nil {
			r.LHS = p.parseFacts(node, factQuery, factQueryCursor)
		}
		if node := captureMap["rule.Act"]; node != nil {
			r.Act = p.parseFacts(node, factQuery, factQueryCursor)
		}
		if node := captureMap["rule.RHS"]; node != nil {
			r.RHS = p.parseFacts(node, factQuery, factQueryCursor)
		}

		// FIX: Need to check how to compute the fix point of formats and expend them
		// in the correct order.
		rules = append(rules, r.Subst(b).ExpandFormats(formats))
	}

	return rules, nil
}

// Parse parses the given source code and returns a tree-sitter tree.
func Parse(ctx context.Context, source []byte) (*sitter.Tree, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	lang := spthy.GetLanguage()
	if err := parser.SetLanguage(lang); err != nil {
		return nil, err
	}

	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	tree := parser.Parse(source, nil)
	if tree == nil {
		return nil, errors.New("failed to parse source")
	}

	return tree, nil
}

// parseRuleAttributes parses the attributes of a rule node and returns a map of attribute key-value pairs.
func (p *Parser) parseRuleAttributes(node *sitter.Node) map[string]rule.Attribute {
	attrs := make(map[string]rule.Attribute)

	for i := uint(0); i < node.ChildCount(); i++ {
		ruleAttr := node.Child(i)
		if ruleAttr.Kind() != "rule_attr" {
			continue
		}
		attrKey := strings.TrimSuffix(ruleAttr.Child(0).Kind(), "=")

		switch attrKey {
		case "hint", "trigger":
			var terms []term.Term
			for _, item := range childrenByFieldName(ruleAttr, "item") {
				terms = append(terms, p.parseTerm(item))
			}
			// FIXME: Ensure that either a hint or trigger is specified.
			attrs[attrKey] = rule.TermAttribute{Value: terms}
		default:
			var attrValue string
			if ruleAttr.ChildCount() > 2 {
				attrValue = ruleAttr.Child(2).Utf8Text(p.src)
			}
			attrs[attrKey] = rule.StringAttribute{Value: attrValue}
		}
	}

	return attrs
}

func (p *Parser) parseLetBlock(node *sitter.Node) *term.Binding {
	b := term.NewBinding()

	for i := uint(0); i < node.ChildCount(); i++ {
		letItem := node.Child(i)
		if letItem.Kind() != "rule_let_term" {
			continue
		}

		left := p.parseTerm(letItem.ChildByFieldName("left"))
		right := p.parseTerm(letItem.ChildByFieldName("right"))

		b.Set(left, right)
	}

	return b.ComputeFixpoint()
}

func (p *Parser) parseMacros(n *sitter.Node) *term.Binding {
	b := term.NewBinding()

	query, err := sitter.NewQuery(p.lang, macroPattern)
	if err != nil {
		return b
	}
	defer query.Close()

	cursor := sitter.NewQueryCursor()
	defer cursor.Close()

	matches := cursor.Matches(query, n, p.src)

	for m := matches.Next(); m != nil; m = matches.Next() {

		captureMap := getCaptureMap(query, m)

		left, ok := captureMap["macro.left"]
		if !ok {
			continue
		}

		right, ok := captureMap["macro.right"]
		if !ok {
			continue
		}

		b.Set(p.parseTerm(left), p.parseTerm(right))
	}

	return b
}

// parsePubName parses a pub_name node and returns a constant.
func (p *Parser) parsePubName(n *sitter.Node) term.Term {
	// FIXME: pub_name wrapped in single quotes.
	name := strings.Trim(n.Utf8Text(p.src), "'")

	if i, err := strconv.Atoi(name); err == nil {
		return term.NewConstant[int](i)
	}

	if strings.HasPrefix(name, "0x") {
		bytes, err := hex.DecodeString(name[2:])
		if err != nil {
			errMsg := fmt.Sprintf("attempt to parse invalid hex string: %s. Does it have even length?\n", name)
			panic(errMsg)
		}

		return term.NewConstant[[]byte](bytes)
	}

	return term.NewConstant[string](name)
}

// traverse a node and print its type and content.
func traverse(node *sitter.Node, depth int) {
	// Print information about the current node
	fmt.Printf("%*sType: %s, Start: %d, End: %d, Node: %v\n", depth*2, "", node.Kind(), node.StartByte(), node.EndByte(), node)

	// Recursively traverse child nodes
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		traverse(child, depth+1)
	}
}
