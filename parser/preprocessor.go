package parser

import (
	"bytes"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Preprocessor holds the state for the preprocessing pass.
type Preprocessor struct {
	source  []byte
	defines map[string]bool
}

// NewPreprocessor creates a new preprocessor.
func NewPreprocessor(source []byte, defines []string) *Preprocessor {
	defs := make(map[string]bool)
	for _, d := range defines {
		defs[d] = true
	}
	return &Preprocessor{
		source:  source,
		defines: defs,
	}
}

// Run processes the AST and returns the preprocessed source code.
func (p *Preprocessor) Run(root *sitter.Node) []byte {
	var out bytes.Buffer
	p.walk(root, &out)
	return out.Bytes()
}

// walk traverses the AST and writes the processed source to the buffer.
func (p *Preprocessor) walk(node *sitter.Node, out *bytes.Buffer) {
	nodeType := node.Kind()

	if nodeType == "preprocessor" {
		// The preprocessor node itself doesn't have content, but it has a child
		// which is the actual directive, e.g., 'ifdef'.
		p.handlePreprocessor(node.Child(0), out)
		return
	}

	// For all other nodes, we need to preserve the original source content
	// including whitespace and newlines. We copy the entire range of the node.
	if node.ChildCount() == 0 {
		// Leaf node: copy its content
		out.Write(p.source[node.StartByte():node.EndByte()])
	} else {
		// Non-leaf node: recursively walk children, but also preserve
		// any whitespace between children by tracking byte positions
		lastEndByte := node.StartByte()

		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)

			// Copy any whitespace/content between the last child and this one
			if child.StartByte() > lastEndByte {
				out.Write(p.source[lastEndByte:child.StartByte()])
			}

			// Process the child
			p.walk(child, out)
			lastEndByte = child.EndByte()
		}

		// Copy any remaining content after the last child
		if node.EndByte() > lastEndByte {
			out.Write(p.source[lastEndByte:node.EndByte()])
		}
	}
}

// handlePreprocessor evaluates a preprocessor directive.
func (p *Preprocessor) handlePreprocessor(node *sitter.Node, out *bytes.Buffer) {
	if node.Kind() == "ifdef" {
		// Use field-based access instead of child indices
		conditionNode := node.ChildByFieldName("condition")

		if conditionNode == nil {
			return // No condition found
		}

		if p.evalCondition(conditionNode) {
			// Condition is true, process all 'consequence' nodes
			consequenceNodes := childrenByFieldName(node, "consequence")
			for _, conseqNode := range consequenceNodes {
				p.walk(conseqNode, out)
			}
		} else {
			// Condition is false, process all 'alternative' nodes if they exist
			alternativeNodes := childrenByFieldName(node, "alternative")
			for _, altNode := range alternativeNodes {
				p.walk(altNode, out)
			}
		}
	}
}

// evalCondition evaluates an ifdef condition node, supporting the grammar's
// nested boolean operators: ident, ifdef_nested, ifdef_not, ifdef_and, ifdef_or.
func (p *Preprocessor) evalCondition(node *sitter.Node) bool {
	switch node.Kind() {
	case "ident":
		return p.defines[node.Utf8Text(p.source)]
	case "ifdef_nested":
		// '(' formula ')'
		for i := uint(0); i < node.ChildCount(); i++ {
			c := node.Child(i)
			if isFormula(c) {
				return p.evalCondition(c)
			}
		}
		return false
	case "ifdef_not":
		// 'not' formula
		for i := uint(0); i < node.ChildCount(); i++ {
			c := node.Child(i)
			if isFormula(c) {
				return !p.evalCondition(c)
			}
		}
		return false
	case "ifdef_and":
		left, right := formulaOperands(node)
		if left == nil || right == nil {
			return false
		}
		return p.evalCondition(left) && p.evalCondition(right)
	case "ifdef_or":
		left, right := formulaOperands(node)
		if left == nil || right == nil {
			return false
		}
		return p.evalCondition(left) || p.evalCondition(right)
	default:
		// Fallback: treat the entire text as a single ident for backward compat.
		return p.defines[node.Utf8Text(p.source)]
	}
}

func isFormula(n *sitter.Node) bool {
	switch n.Kind() {
	case "ident", "ifdef_nested", "ifdef_not", "ifdef_and", "ifdef_or":
		return true
	}
	return false
}

func formulaOperands(node *sitter.Node) (*sitter.Node, *sitter.Node) {
	var left, right *sitter.Node
	for i := uint(0); i < node.ChildCount(); i++ {
		c := node.Child(i)
		if !isFormula(c) {
			continue
		}
		if left == nil {
			left = c
		} else {
			right = c
			break
		}
	}
	return left, right
}
