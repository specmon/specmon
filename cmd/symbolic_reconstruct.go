package cmd

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/fatih/color"
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
	index     int
	name      string
	symbolic  string
	concrete  []string
	retSym    string
	retValue  string
	inputVars []string
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

type symbolExpandCache struct {
	expr map[string]string
	vars map[string]string
}

func buildSymbolic(events []eventInfo, opts symbolicOptions) ([]symEvent, []symVar, []computedTerm) {
	// Build symbolic events, variable assignments, and computed terms.
	vars := make(map[string]symVar)
	varsByName := make(map[string]symVar)
	var order []string
	var eventsOut []symEvent
	var computed []computedTerm
	producers := make(map[string]string)

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
		varsByName[v.name] = v
		order = append(order, key)
		return v
	}

	for _, ev := range events {
		// Normalize event names and arguments before symbolizing.
		name := normalizeSymbolicName(ev.name, opts.detectCrypto)
		cleanArgs := cleanSymbolicArgs(ev.args)
		symArgs, concrete, usedVars, argVars := symbolicArgs(ev.index, cleanArgs, vars, assignVar)

		outputVar := ""
		outputArgPos := 0
		retValue := ""
		hasReturn := false
		if out, ok := eventReturnBytes(ev.raw); ok {
			hasReturn = true
			retValue = "0x" + hex.EncodeToString(out)
			key := string(out)
			if v, ok := vars[key]; ok {
				outputVar = v.name
			} else {
				v := assignVar(key, retValue, ev.index, 0)
				outputVar = v.name
			}
			if len(argVars) > 0 && argVars[len(argVars)-1] == outputVar {
				outputArgPos = len(argVars)
			} else {
				outputArgPos = len(argVars) + 1
			}
		}
		if outputVar == "" && opts.detectCrypto {
			outputVar, outputArgPos = inferOutputVar(name, argVars, varsByName, ev.index)
		}
		nestedArgs := append([]string(nil), symArgs...)
		expandCache := newSymbolExpandCache()
		for i, a := range nestedArgs {
			nestedArgs[i] = expandExprWithProducersCached(strings.TrimSpace(a), producers, expandCache, map[string]bool{})
		}
		symbolic := fmt.Sprintf("%s(%s)", name, strings.Join(nestedArgs, ", "))
		if hasReturn && outputVar != "" {
			symbolic = fmt.Sprintf("%s → %s", symbolic, outputVar)
		}
		eventsOut = append(eventsOut, symEvent{
			index:     ev.index,
			name:      name,
			symbolic:  symbolic,
			concrete:  concrete,
			retSym:    outputVar,
			retValue:  retValue,
			inputVars: uniqueStrings(usedVars),
		})

		if name != "" {
			// Treat non-receive events as computed terms.
			ct := computedTerm{
				name:         fmt.Sprintf("t%d", ev.index),
				eventIdx:     ev.index,
				method:       strings.ToLower(name),
				fnName:       name,
				expr:         fmt.Sprintf("%s(%s)", name, strings.Join(symArgs, ", ")),
				args:         append([]string(nil), symArgs...),
				outputVar:    outputVar,
				outputArgPos: outputArgPos,
				inputVars:    uniqueStrings(usedVars),
			}
			computed = append(computed, ct)
			if outputVar != "" {
				producers[outputVar] = nestedCoreExpr(ct, producers, newSymbolExpandCache())
			}
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
	// Keep user-defined event/function names unchanged.
	return name
}

func cleanSymbolicArgs(args []term.Term) []term.Term {
	// Drop only a trailing empty pair.
	clean := args
	if len(clean) > 0 && isEmptyPair(clean[len(clean)-1]) {
		clean = clean[:len(clean)-1]
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

func inferOutputVar(name string, argVars []string, varsByName map[string]symVar, eventIdx int) (string, int) {
	// For explicit-output APIs, treat the last new variable as output.
	_ = name
	if len(argVars) < 2 {
		return "", 0
	}
	last := argVars[len(argVars)-1]
	if last == "" {
		return "", 0
	}
	if v, ok := varsByName[last]; ok && v.eventIdx == eventIdx {
		return last, len(argVars)
	}
	return "", 0
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
			if opts.showProvenance {
				if prov := renderStdoutProvenance(ev); prov != "" {
					lines = append(lines, strings.Repeat(" ", 8)+prov)
				}
			}
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
			if ev.retValue != "" {
				line += fmt.Sprintf(" → [%s]", ev.retValue)
			}
		} else if ev.retValue != "" {
			pad := concreteColumn - visibleTextWidth(prefix)
			if pad < 1 {
				pad = 1
			}
			line = fmt.Sprintf("%s%s[%s]", prefix, strings.Repeat(" ", pad), ev.retValue)
		}
		lines = append(lines, line)
		if opts.showProvenance {
			if prov := renderStdoutProvenance(ev); prov != "" {
				lines = append(lines, strings.Repeat(" ", 8)+prov)
			}
		}
	}
	return lines
}

func renderStdoutProvenance(ev symEvent) string {
	var parts []string
	if len(ev.inputVars) > 0 {
		parts = append(parts, fmt.Sprintf("uses %s", strings.Join(ev.inputVars, ", ")))
	}
	if ev.retSym != "" {
		parts = append(parts, fmt.Sprintf("produces %s", ev.retSym))
	}
	if len(parts) == 0 {
		return ""
	}
	label := "provenance: " + strings.Join(parts, " -> ")
	if color.NoColor {
		return label
	}
	return color.New(color.FgHiBlack).Sprint(label)
}

func buildSymbolicReport(events []symEvent, vars []symVar, computed []computedTerm, opts symbolicOptions) string {
	// Build the term report: variables, computed terms, and provenance.
	var b strings.Builder
	eventTokens := make(map[int]map[string]struct{}, len(events))
	for _, ev := range events {
		eventTokens[ev.index] = extractExprTokenSet(ev.symbolic)
	}
	computedTokens := make(map[int]map[string]struct{}, len(computed))
	for _, ct := range computed {
		computedTokens[ct.eventIdx] = extractExprTokenSet(ct.expr)
	}
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
		expandCache := newSymbolExpandCache()
		for _, ct := range computed {
			if ct.outputVar == "" {
				continue
			}
			tracked := []string{ct.outputVar}
			usedIn := findValueReuseEvents(events, eventTokens, ct.eventIdx, tracked)
			computedUses := findComputedReuse(computed, computedTokens, ct.eventIdx, tracked)
			nested := buildNestedVersion(ct, producers, expandCache)

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
			producers[ct.outputVar] = nestedCoreExpr(ct, producers, expandCache)
		}
		b.WriteString("\n")
	}

	if opts.showProvenance {
		// Track where each variable appears in the symbolic trace.
		b.WriteString("Variable Provenance:\n")
		usage := make(map[string][]int)
		for _, ev := range events {
			for _, v := range vars {
				if tokenSetContains(eventTokens[ev.index], v.name) {
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

func buildNestedVersion(ct computedTerm, producers map[string]string, cache *symbolExpandCache) string {
	core := nestedCoreExpr(ct, producers, cache)
	if ct.outputVar == "" {
		return core
	}
	return fmt.Sprintf("%s = %s", core, ct.outputVar)
}

func nestedCoreExpr(ct computedTerm, producers map[string]string, cache *symbolExpandCache) string {
	args := append([]string(nil), ct.args...)
	if ct.outputArgPos > 0 && ct.outputArgPos <= len(args) {
		idx := ct.outputArgPos - 1
		args = append(args[:idx], args[idx+1:]...)
	}
	for i, a := range args {
		args[i] = expandExprWithProducersCached(strings.TrimSpace(a), producers, cache, map[string]bool{})
	}
	return fmt.Sprintf("%s(%s)", ct.fnName, strings.Join(args, ", "))
}

func newSymbolExpandCache() *symbolExpandCache {
	return &symbolExpandCache{
		expr: make(map[string]string),
		vars: make(map[string]string),
	}
}

func expandExprWithProducersCached(expr string, producers map[string]string, cache *symbolExpandCache, stack map[string]bool) string {
	if expr == "" {
		return expr
	}
	if cache != nil {
		if expanded, ok := cache.expr[expr]; ok {
			return expanded
		}
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
			b.WriteString(expandVarToken(tok, producers, cache, stack))
			i = j
			continue
		}
		b.WriteRune(r)
		i++
	}
	expanded := b.String()
	if cache != nil {
		cache.expr[expr] = expanded
	}
	return expanded
}

func expandVarToken(tok string, producers map[string]string, cache *symbolExpandCache, stack map[string]bool) string {
	if !isVarToken(tok) {
		return tok
	}
	if cache != nil {
		if expanded, ok := cache.vars[tok]; ok {
			return expanded
		}
	}
	prod, ok := producers[tok]
	if !ok {
		return tok
	}
	if stack[tok] {
		return tok
	}
	stack[tok] = true
	expanded := expandExprWithProducersCached(prod, producers, cache, stack)
	delete(stack, tok)
	if cache != nil {
		cache.vars[tok] = expanded
	}
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

func findValueReuseEvents(events []symEvent, eventTokens map[int]map[string]struct{}, fromEvent int, varNames []string) []int {
	if len(varNames) == 0 {
		return nil
	}
	var usedIn []int
	for _, ev := range events {
		if ev.index <= fromEvent {
			continue
		}
		for _, vn := range varNames {
			if tokenSetContains(eventTokens[ev.index], vn) {
				usedIn = append(usedIn, ev.index)
				break
			}
		}
	}
	return uniqueInts(usedIn)
}

func findComputedReuse(computed []computedTerm, computedTokens map[int]map[string]struct{}, fromEvent int, varNames []string) []string {
	if len(varNames) == 0 {
		return nil
	}
	var out []string
	for _, ct := range computed {
		if ct.eventIdx <= fromEvent {
			continue
		}
		if tokenSetContainsAny(computedTokens[ct.eventIdx], varNames) {
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

func extractExprTokenSet(expr string) map[string]struct{} {
	tokens := extractExprTokens(expr)
	if len(tokens) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(tokens))
	for _, tok := range tokens {
		set[tok] = struct{}{}
	}
	return set
}

func tokenSetContains(tokens map[string]struct{}, varName string) bool {
	if len(tokens) == 0 || varName == "" {
		return false
	}
	_, ok := tokens[varName]
	return ok
}

func tokenSetContainsAny(tokens map[string]struct{}, vars []string) bool {
	if len(tokens) == 0 || len(vars) == 0 {
		return false
	}
	for _, v := range vars {
		if tokenSetContains(tokens, v) {
			return true
		}
	}
	return false
}
