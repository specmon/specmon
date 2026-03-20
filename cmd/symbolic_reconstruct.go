package cmd

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/specmon/specmon/term"
)

type symbolicOptions struct {
	showConcrete   bool
	showProvenance bool
	detectCrypto   bool
}

type symVar struct {
	name     string
	value    string
	eventIdx int
	argIdx   int
}

type symEvent struct {
	index    int
	name     string
	symbolic string
	concrete []string
}

type computedTerm struct {
	name         string
	eventIdx     int
	method       string
	fnName       string
	expr         string
	args         []string
	outputVar    string
	outputArgPos int
	inputVars    []string
}

func buildSymbolic(events []eventInfo, opts symbolicOptions) ([]symEvent, []symVar, []computedTerm) {
	// Build symbolic events, variable assignments, and computed terms.
	vars := make(map[string]symVar)
	var order []string
	var eventsOut []symEvent
	var computed []computedTerm

	nextVar := 1
	assignVar := func(key string, value string, evIdx, argIdx int) symVar {
		// Allocate a new symbolic variable name.
		v := symVar{
			name:     fmt.Sprintf("x%d", nextVar),
			value:    value,
			eventIdx: evIdx,
			argIdx:   argIdx,
		}
		nextVar++
		vars[key] = v
		order = append(order, key)
		return v
	}

	for _, ev := range events {
		// Normalize event names and arguments before symbolizing.
		name := normalizeSymbolicName(ev.name, opts.detectCrypto)
		cleanArgs := cleanSymbolicArgs(name, ev.args)
		symArgs, concrete, usedVars, argVars := symbolicArgs(ev.index, cleanArgs, vars, assignVar)
		symbolic := fmt.Sprintf("%s(%s)", name, strings.Join(symArgs, ", "))
		eventsOut = append(eventsOut, symEvent{
			index:    ev.index,
			name:     name,
			symbolic: symbolic,
			concrete: concrete,
		})

		outputVar := ""
		outputArgPos := 0
		if out, ok := eventReturnBytes(ev.raw); ok {
			key := string(out)
			if v, ok := vars[key]; ok {
				outputVar = v.name
			} else {
				val := "0x" + hex.EncodeToString(out)
				v := assignVar(key, val, ev.index, 0)
				outputVar = v.name
			}
			if len(argVars) > 0 && argVars[len(argVars)-1] == outputVar {
				outputArgPos = len(argVars)
			} else {
				outputArgPos = len(argVars) + 1
			}
		}
		if outputVar == "" {
			outputVar, outputArgPos = inferOutputVar(name, argVars, vars, ev.index)
		}

		if name != "" && name != "recv" && name != "receive" && name != "in" {
			// Treat non-receive events as computed terms.
			computed = append(computed, computedTerm{
				name:         fmt.Sprintf("t%d", ev.index),
				eventIdx:     ev.index,
				method:       strings.ToLower(name),
				fnName:       name,
				expr:         symbolic,
				args:         append([]string(nil), symArgs...),
				outputVar:    outputVar,
				outputArgPos: outputArgPos,
				inputVars:    uniqueStrings(usedVars),
			})
		}
	}

	var varList []symVar
	for _, key := range order {
		varList = append(varList, vars[key])
	}

	return eventsOut, varList, computed
}

func eventReturnBytes(raw term.Term) ([]byte, bool) {
	fn, err := term.AsFunction(raw)
	if err != nil || fn == nil {
		return nil, false
	}
	if fn.Name != term.PairFunctionName || len(fn.Args) != 2 {
		return nil, false
	}
	b, err := term.AsBytes(fn.Args[1])
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

func normalizeSymbolicName(name string, detectCrypto bool) string {
	// Optionally collapse crypto operations into a generic "compute" label.
	if detectCrypto {
		return name
	}
	switch strings.ToLower(name) {
	case "hash", "h", "hmac", "mac", "enc", "encrypt", "dec", "decrypt":
		return "compute"
	default:
		return name
	}
}

func cleanSymbolicArgs(name string, args []term.Term) []term.Term {
	// Drop trailing empty pairs and simplify recv/in events to payload only.
	clean := args
	if len(clean) > 0 && isEmptyPair(clean[len(clean)-1]) {
		clean = clean[:len(clean)-1]
	}
	switch strings.ToLower(name) {
	case "recv", "receive", "in":
		if len(clean) >= 2 {
			return clean[len(clean)-1:]
		}
	}
	return clean
}

func isEmptyPair(t term.Term) bool {
	// Detect the empty pair <>.
	fn, err := term.AsFunction(t)
	if err != nil || fn == nil {
		return false
	}
	return fn.Name == term.PairFunctionName && len(fn.Args) == 0
}

func symbolicArgs(
	eventIdx int,
	args []term.Term,
	vars map[string]symVar,
	assign func(key, value string, evIdx, argIdx int) symVar,
) ([]string, []string, []string, []string) {
	// Replace byte arguments with symbolic variables, keep non-bytes readable.
	var symArgs []string
	var concrete []string
	var used []string
	argVars := make([]string, len(args))

	for i, arg := range args {
		if b, ok := bytesOf(arg); ok {
			// Byte args become x1, x2, ... with concrete hex captured.
			key := string(b)
			if v, ok := vars[key]; ok {
				symArgs = append(symArgs, v.name)
				used = append(used, v.name)
				argVars[i] = v.name
			} else {
				val := "0x" + hex.EncodeToString(b)
				v := assign(key, val, eventIdx, i+1)
				symArgs = append(symArgs, v.name)
				used = append(used, v.name)
				argVars[i] = v.name
			}
			concrete = append(concrete, "0x"+hex.EncodeToString(b))
		} else {
			// Non-byte args keep verbose formatting.
			symArgs = append(symArgs, formatVerboseTerm(arg))
		}
	}
	return symArgs, concrete, used, argVars
}

func inferOutputVar(name string, argVars []string, vars map[string]symVar, eventIdx int) (string, int) {
	// For explicit-output APIs (e.g. h(x, y)), treat the last new variable as output.
	if len(argVars) < 2 || isStateEvent(name) {
		return "", 0
	}
	last := argVars[len(argVars)-1]
	if last == "" {
		return "", 0
	}
	if v, ok := findVarByName(vars, last); ok && v.eventIdx == eventIdx {
		return last, len(argVars)
	}
	return "", 0
}

func findVarByName(vars map[string]symVar, name string) (symVar, bool) {
	for _, v := range vars {
		if v.name == name {
			return v, true
		}
	}
	return symVar{}, false
}

func isStateEvent(name string) bool {
	switch strings.ToLower(name) {
	case "setup", "init", "send", "recv", "receive", "in", "out", "trace":
		return true
	default:
		return false
	}
}

func bytesOf(t term.Term) ([]byte, bool) {
	// Extract non-empty byte constants from a term.
	b, err := term.AsBytes(t)
	if err != nil {
		return nil, false
	}
	if len(b) == 0 {
		return nil, false
	}
	return b, true
}

func renderSymbolicLines(events []symEvent, opts symbolicOptions) []string {
	// Render symbolic events as text lines, optionally with concrete bytes.
	if !opts.showConcrete {
		lines := make([]string, 0, len(events))
		for _, ev := range events {
			line := ev.symbolic
			if strings.HasPrefix(line, ev.name+"(") {
				line = colorEventName(ev.name) + line[len(ev.name):]
			}
			lines = append(lines, fmt.Sprintf("%s %4d  %s", successMarker(), ev.index, line))
		}
		return lines
	}

	rendered := make([]string, len(events))
	maxPrefixWidth := 0
	for i, ev := range events {
		line := ev.symbolic
		if strings.HasPrefix(line, ev.name+"(") {
			line = colorEventName(ev.name) + line[len(ev.name):]
		}
		prefix := fmt.Sprintf("%s %4d  %s", successMarker(), ev.index, line)
		rendered[i] = prefix
		if w := visibleTextWidth(prefix); w > maxPrefixWidth {
			maxPrefixWidth = w
		}
	}

	concreteColumn := maxPrefixWidth + 2
	lines := make([]string, 0, len(events))
	for i, ev := range events {
		prefix := rendered[i]
		line := prefix
		if len(ev.concrete) > 0 {
			pad := concreteColumn - visibleTextWidth(prefix)
			if pad < 1 {
				pad = 1
			}
			line = fmt.Sprintf("%s%s[%s]", prefix, strings.Repeat(" ", pad), strings.Join(ev.concrete, ", "))
		}
		lines = append(lines, line)
	}
	return lines
}

func buildSymbolicReport(events []symEvent, vars []symVar, computed []computedTerm, opts symbolicOptions) string {
	// Build the term report: variables, computed terms, and provenance.
	var b strings.Builder
	b.WriteString("Symbolic Reconstruction Report\n")
	b.WriteString("===============================\n\n")

	b.WriteString("Variables:\n")
	if len(vars) == 0 {
		b.WriteString("  (none)\n\n")
	} else {
		for _, v := range vars {
			fmt.Fprintf(&b, "  %s = %s  (from event %d, arg %d)\n", v.name, v.value, v.eventIdx, v.argIdx)
		}
		b.WriteString("\n")
	}

	b.WriteString("Computed Terms:\n")
	if len(computed) == 0 {
		b.WriteString("  (none)\n\n")
	} else {
		for _, ct := range computed {
			fmt.Fprintf(&b, "  %s = %s\n", ct.name, ct.expr)
		}
		b.WriteString("\n")
	}

	hasTracked := false
	for _, ct := range computed {
		if ct.outputVar != "" {
			hasTracked = true
			break
		}
	}
	if hasTracked {
		b.WriteString("Computed Term Reuse:\n")
		producers := map[string]string{}
		for _, ct := range computed {
			if ct.outputVar == "" {
				continue
			}
			tracked := []string{ct.outputVar}
			usedIn := findValueReuseEvents(events, ct.eventIdx, tracked)
			computedUses := findComputedReuse(computed, ct.eventIdx, tracked)
			nested := buildNestedVersion(ct, producers)

			fmt.Fprintf(&b, "  %s: %s\n", ct.name, ct.expr)
			fmt.Fprintf(&b, "    nested version: %s\n", nested)
			fmt.Fprintf(&b, "    output: %s", ct.outputVar)
			if ct.outputArgPos > 0 {
				fmt.Fprintf(&b, " (arg %d)", ct.outputArgPos)
			}
			b.WriteString("\n")
			if len(computedUses) > 0 {
				fmt.Fprintf(&b, "    used by computed terms: %s\n", strings.Join(computedUses, ", "))
			} else {
				fmt.Fprintf(&b, "    used by computed terms: (none)\n")
			}
			if len(usedIn) > 0 {
				fmt.Fprintf(&b, "    used in events: %s\n", joinInts(usedIn))
			} else {
				fmt.Fprintf(&b, "    used in events: (none)\n")
			}
			b.WriteString("\n")
			producers[ct.outputVar] = nestedCoreExpr(ct, producers)
		}
		b.WriteString("\n")
	}

	if opts.showProvenance {
		// Track where each variable appears in the symbolic trace.
		b.WriteString("Variable Provenance:\n")
		usage := make(map[string][]int)
		for _, ev := range events {
			for _, v := range vars {
				if exprContainsVar(ev.symbolic, v.name) {
					usage[v.name] = append(usage[v.name], ev.index)
				}
			}
		}
		var keys []string
		for k := range usage {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			ii, iok := parseVarIndex(keys[i])
			jj, jok := parseVarIndex(keys[j])
			if iok && jok {
				if ii == jj {
					return keys[i] < keys[j]
				}
				return ii < jj
			}
			if iok != jok {
				return iok
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s: used in events %s\n", k, joinInts(usage[k]))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func buildNestedVersion(ct computedTerm, producers map[string]string) string {
	core := nestedCoreExpr(ct, producers)
	if ct.outputVar == "" {
		return core
	}
	return fmt.Sprintf("%s = %s", core, ct.outputVar)
}

func nestedCoreExpr(ct computedTerm, producers map[string]string) string {
	args := append([]string(nil), ct.args...)
	if ct.outputArgPos > 0 && ct.outputArgPos <= len(args) {
		idx := ct.outputArgPos - 1
		args = append(args[:idx], args[idx+1:]...)
	}
	for i, a := range args {
		args[i] = expandExprWithProducers(strings.TrimSpace(a), producers, map[string]bool{})
	}
	return fmt.Sprintf("%s(%s)", ct.fnName, strings.Join(args, ", "))
}

func expandExprWithProducers(expr string, producers map[string]string, stack map[string]bool) string {
	if expr == "" {
		return expr
	}
	var b strings.Builder
	runes := []rune(expr)
	for i := 0; i < len(runes); {
		r := runes[i]
		if isTokenRune(r) {
			j := i + 1
			for j < len(runes) && isTokenRune(runes[j]) {
				j++
			}
			tok := string(runes[i:j])
			b.WriteString(expandVarToken(tok, producers, stack))
			i = j
			continue
		}
		b.WriteRune(r)
		i++
	}
	return b.String()
}

func expandVarToken(tok string, producers map[string]string, stack map[string]bool) string {
	if !isVarToken(tok) {
		return tok
	}
	prod, ok := producers[tok]
	if !ok {
		return tok
	}
	if stack[tok] {
		return tok
	}
	stack[tok] = true
	expanded := expandExprWithProducers(prod, producers, stack)
	delete(stack, tok)
	return expanded
}

func isTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func isVarToken(tok string) bool {
	if tok == "" || !isTokenRune(rune(tok[0])) {
		return false
	}
	for _, r := range tok {
		if !isTokenRune(r) {
			return false
		}
	}
	return true
}

func findValueReuseEvents(events []symEvent, fromEvent int, varNames []string) []int {
	if len(varNames) == 0 {
		return nil
	}
	var usedIn []int
	for _, ev := range events {
		if ev.index <= fromEvent {
			continue
		}
		for _, vn := range varNames {
			if exprContainsVar(ev.symbolic, vn) {
				usedIn = append(usedIn, ev.index)
				break
			}
		}
	}
	return uniqueInts(usedIn)
}

func findComputedReuse(computed []computedTerm, fromEvent int, varNames []string) []string {
	if len(varNames) == 0 {
		return nil
	}
	var out []string
	for _, ct := range computed {
		if ct.eventIdx <= fromEvent {
			continue
		}
		if containsAnyVar(ct.expr, varNames) {
			out = append(out, fmt.Sprintf("%s(event %d)", ct.name, ct.eventIdx))
		}
	}
	return out
}

func joinInts(vals []int) string {
	// Join a list of ints into a sorted, comma-separated string.
	sort.Ints(vals)
	var out []string
	for _, v := range vals {
		out = append(out, fmt.Sprintf("%d", v))
	}
	return strings.Join(out, ", ")
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func uniqueInts(in []int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(in))
	for _, n := range in {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func containsAllVars(symbolic string, vars []string) bool {
	for _, v := range vars {
		if !exprContainsVar(symbolic, v) {
			return false
		}
	}
	return true
}

func containsAnyVar(symbolic string, vars []string) bool {
	for _, v := range vars {
		if exprContainsVar(symbolic, v) {
			return true
		}
	}
	return false
}

func exprContainsVar(symbolic, varName string) bool {
	if symbolic == "" || varName == "" {
		return false
	}
	for _, tok := range extractExprTokens(symbolic) {
		if tok == varName {
			return true
		}
	}
	return false
}

func parseVarIndex(name string) (int, bool) {
	if len(name) < 2 || name[0] != 'x' {
		return 0, false
	}
	n, err := strconv.Atoi(name[1:])
	if err != nil {
		return 0, false
	}
	return n, true
}

func extractExprTokens(expr string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) == 0 {
			return
		}
		out = append(out, string(cur))
		cur = cur[:0]
	}
	for _, r := range expr {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			cur = append(cur, r)
			continue
		}
		flush()
	}
	flush()
	return out
}
