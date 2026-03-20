package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/specmon/specmon/term"
)

type inferOptions struct {
	minComponentLength int
	maxComponents      int
	confidenceLevel    string
}

type eventInfo struct {
	index int
	name  string
	args  []term.Term
	raw   term.Term
}

type valueRef struct {
	eventIndex int
	argIndex   int
	bytes      []byte
}

type inference struct {
	eventIndex int
	eventName  string
	expr       string
	lengthExpr string
	confidence string
}

func buildEventInfo(index int, t term.Term) (eventInfo, bool) {
	// Normalize a term into name/args form and attach its index.
	name, args, ok := eventCall(t)
	if !ok {
		return eventInfo{}, false
	}
	return eventInfo{
		index: index,
		name:  name,
		args:  args,
		raw:   t,
	}, true
}

func inferFormats(events []eventInfo, opts inferOptions) (map[int]string, []inference) {
	// Walk events and infer simple format relationships between byte arguments.
	annotations := make(map[int]string)
	var inferences []inference

	var prevValues []valueRef
	for _, ev := range events {
		byteArgs := extractByteArgs(ev.args)
		if len(byteArgs) == 0 {
			continue
		}
		// Annotate only the first byte argument to keep output readable.
		arg := byteArgs[0]
		expr, confidence, ok := inferExpression(arg.bytes, prevValues, opts)
		if ok && allowConfidence(confidence, opts.confidenceLevel) {
			lengthExpr := inferLengthShape(expr, prevValues)
			annotation := fmt.Sprintf("  # inferred: %s(%s)", ev.name, expr)
			annotations[ev.index] = annotation
			inferences = append(inferences, inference{
				eventIndex: ev.index,
				eventName:  ev.name,
				expr:       expr,
				lengthExpr: lengthExpr,
				confidence: confidence,
			})
		}

		for _, arg := range byteArgs {
			prevValues = append(prevValues, valueRef{
				eventIndex: ev.index,
				argIndex:   arg.index,
				bytes:      arg.bytes,
			})
		}
	}

	return annotations, inferences
}

func allowConfidence(confidence, level string) bool {
	// Apply the confidence filter requested by the user.
	level = strings.ToUpper(level)
	confidence = strings.ToUpper(confidence)
	if level == "" || level == "MEDIUM" {
		return confidence == "HIGH" || confidence == "MEDIUM"
	}
	if level == "ALL" {
		return true
	}
	if level == "HIGH" {
		return confidence == "HIGH"
	}
	if level == "LOW" {
		return confidence == "HIGH" || confidence == "MEDIUM" || confidence == "LOW"
	}
	return confidence == "HIGH" || confidence == "MEDIUM"
}

func inferExpression(value []byte, prev []valueRef, opts inferOptions) (string, string, bool) {
	// Try each inference heuristic in priority order.
	if len(value) == 0 || len(prev) == 0 {
		return "", "", false
	}
	minLen := opts.minComponentLength
	if minLen <= 0 {
		minLen = 2
	}
	maxComp := opts.maxComponents
	if maxComp <= 0 {
		maxComp = 10
	}

	if refs, ok := findConcat(value, prev, minLen, maxComp); ok {
		var parts []string
		for _, ref := range refs {
			parts = append(parts, formatRef(ref))
		}
		return fmt.Sprintf("cat(%s)", strings.Join(parts, ", ")), "HIGH", true
	}

	if expr, ok := findTagPayload(value, prev, minLen); ok {
		return expr, "MEDIUM", true
	}

	if expr, ok := findLengthPrefix(value, prev, minLen); ok {
		return expr, "MEDIUM", true
	}

	if expr, ok := findPrefixSuffix(value, prev, minLen); ok {
		return expr, "LOW", true
	}

	return "", "", false
}

func findConcat(value []byte, prev []valueRef, minLen, maxComp int) ([]valueRef, bool) {
	// Search for a concatenation of previous byte values that matches "value".
	lengths := uniqueLengths(prev, minLen)
	if len(lengths) == 0 {
		return nil, false
	}
	refMap := map[string][]valueRef{}
	for _, ref := range prev {
		if len(ref.bytes) < minLen {
			continue
		}
		key := string(ref.bytes)
		refMap[key] = append(refMap[key], ref)
	}
	type node struct {
		pos  int
		path []valueRef
	}
	queue := []node{{pos: 0}}
	seen := make(map[int]int)
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if n.pos == len(value) && len(n.path) >= 2 {
			return n.path, true
		}
		if len(n.path) >= maxComp {
			continue
		}
		if best, ok := seen[n.pos]; ok && best <= len(n.path) {
			continue
		}
		seen[n.pos] = len(n.path)
		for _, l := range lengths {
			if n.pos+l > len(value) {
				continue
			}
			seg := value[n.pos : n.pos+l]
			if refs, ok := refMap[string(seg)]; ok {
				for _, ref := range refs {
					path := append(append([]valueRef{}, n.path...), ref)
					queue = append(queue, node{pos: n.pos + l, path: path})
				}
			}
		}
	}
	return nil, false
}

func findTagPayload(value []byte, prev []valueRef, minLen int) (string, bool) {
	// Detect a one-byte tag followed by a known payload.
	if len(value) < 2 {
		return "", false
	}
	tag := value[:1]
	rest := value[1:]
	for _, ref := range prev {
		if len(ref.bytes) < minLen {
			continue
		}
		if bytes.Equal(ref.bytes, rest) {
			return fmt.Sprintf("cat(byte(%s), %s)", formatBytesShort(tag), formatRef(ref)), true
		}
	}
	return "", false
}

func findLengthPrefix(value []byte, prev []valueRef, minLen int) (string, bool) {
	// Detect a 2-byte length prefix followed by a known payload.
	if len(value) < 3 {
		return "", false
	}
	prefix := value[:2]
	rest := value[2:]
	length := int(binary.BigEndian.Uint16(prefix))
	if length != len(rest) {
		return "", false
	}
	for _, ref := range prev {
		if len(ref.bytes) < minLen {
			continue
		}
		if bytes.Equal(ref.bytes, rest) {
			return fmt.Sprintf("cat(len:2, %s)", formatRef(ref)), true
		}
	}
	return fmt.Sprintf("cat(len:2, %s)", formatBytesShort(rest)), true
}

func findPrefixSuffix(value []byte, prev []valueRef, minLen int) (string, bool) {
	// Detect known prefixes or suffixes and describe the rest as raw bytes.
	best := valueRef{}
	bestPrefix := true
	bestLen := 0
	for _, ref := range prev {
		if len(ref.bytes) < minLen {
			continue
		}
		if len(ref.bytes) >= len(value) {
			continue
		}
		if bytes.HasPrefix(value, ref.bytes) && len(ref.bytes) > bestLen {
			best = ref
			bestPrefix = true
			bestLen = len(ref.bytes)
		}
		if bytes.HasSuffix(value, ref.bytes) && len(ref.bytes) > bestLen {
			best = ref
			bestPrefix = false
			bestLen = len(ref.bytes)
		}
	}
	if bestLen == 0 {
		return "", false
	}
	restLen := len(value) - bestLen
	if restLen < minLen {
		return "", false
	}
	rest := formatBytesShort(value[bestLen:])
	if !bestPrefix {
		rest = formatBytesShort(value[:restLen])
		return fmt.Sprintf("cat(%s, %s)", rest, formatRef(best)), true
	}
	return fmt.Sprintf("cat(%s, %s)", formatRef(best), rest), true
}

type byteArg struct {
	index int
	bytes []byte
}

func extractByteArgs(args []term.Term) []byteArg {
	// Pull out only byte arguments with their 1-based positions.
	var out []byteArg
	for i, arg := range args {
		b, err := term.AsBytes(arg)
		if err != nil {
			continue
		}
		if len(b) == 0 {
			continue
		}
		out = append(out, byteArg{index: i + 1, bytes: b})
	}
	return out
}

func uniqueLengths(prev []valueRef, minLen int) []int {
	// Collect unique byte lengths to guide concatenation search.
	seen := map[int]struct{}{}
	for _, ref := range prev {
		if len(ref.bytes) < minLen {
			continue
		}
		seen[len(ref.bytes)] = struct{}{}
	}
	var lengths []int
	for l := range seen {
		lengths = append(lengths, l)
	}
	sort.Ints(lengths)
	return lengths
}

func formatRef(ref valueRef) string {
	// Human-readable reference to a prior event argument.
	return fmt.Sprintf("e%d_a%d", ref.eventIndex, ref.argIndex)
}

func formatBytesShort(b []byte) string {
	// Short display for byte slices (hex for tiny, length for larger).
	if len(b) == 0 {
		return "<bytes:0>"
	}
	if len(b) <= 4 {
		return fmt.Sprintf("0x%s", fmt.Sprintf("%x", b))
	}
	return fmt.Sprintf("<bytes:%d>", len(b))
}

func eventCall(t term.Term) (string, []term.Term, bool) {
	// Normalize pair-wrapped calls into name + args.
	fn, err := term.AsFunction(t)
	if err != nil || fn == nil {
		return "", nil, false
	}
	if fn.Name == term.PairFunctionName && len(fn.Args) == 2 {
		if call, err := term.AsFunction(fn.Args[0]); err == nil && call != nil {
			args := append([]term.Term{}, call.Args...)
			args = append(args, fn.Args[1])
			return call.Name, args, true
		}
	}
	return fn.Name, fn.Args, true
}

func buildFormatReport(inferences []inference) string {
	// Build a summary + detailed report for format inference results.
	if len(inferences) == 0 {
		return "Format Inference Report\n=======================\n\n(no inferences)\n"
	}
	type key struct {
		name string
		expr string
	}
	type patternKey struct {
		name  string
		shape string
	}

	grouped := map[key][]inference{}
	shapeGrouped := map[patternKey][]inference{}
	eventTotals := map[string]int{}
	byEvent := map[string][]key{}
	for _, inf := range inferences {
		k := key{name: inf.eventName, expr: inf.expr}
		grouped[k] = append(grouped[k], inf)
		shape := strings.TrimSpace(inf.lengthExpr)
		if shape == "" {
			shape = normalizeExprShape(inf.expr)
		}
		sk := patternKey{name: inf.eventName, shape: shape}
		shapeGrouped[sk] = append(shapeGrouped[sk], inf)
		eventTotals[inf.eventName]++
	}
	var keys []key
	for k := range grouped {
		keys = append(keys, k)
		byEvent[k.name] = append(byEvent[k.name], k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name == keys[j].name {
			return keys[i].expr < keys[j].expr
		}
		return keys[i].name < keys[j].name
	})

	var b strings.Builder
	b.WriteString("Format Inference Report\n")
	b.WriteString("=======================\n\n")

	// Summary section: highlight repeated/recurring format shapes first.
	b.WriteString("Summary:\n")
	b.WriteString(fmt.Sprintf("  Total inferences: %d\n", len(inferences)))
	var eventNames []string
	for name := range eventTotals {
		eventNames = append(eventNames, name)
	}
	sort.Strings(eventNames)
	for _, name := range eventNames {
		var patterns []patternKey
		for sk := range shapeGrouped {
			if sk.name == name {
				patterns = append(patterns, sk)
			}
		}
		sort.Slice(patterns, func(i, j int) bool {
			li := len(shapeGrouped[patterns[i]])
			lj := len(shapeGrouped[patterns[j]])
			if li == lj {
				return patterns[i].shape < patterns[j].shape
			}
			return li > lj
		})
		if len(patterns) == 0 {
			continue
		}
		top := patterns[0]
		fmt.Fprintf(&b, "  %s:\n", name)
		fmt.Fprintf(&b, "    Count: %d inference%s\n", eventTotals[name], plural(eventTotals[name]))
		fmt.Fprintf(&b, "    Dominant pattern: %s(%s)\n", name, top.shape)
	}
	b.WriteString("\n")
	b.WriteString("Detailed Patterns:\n")
	for _, name := range eventNames {
		eventKeys := byEvent[name]
		sort.Slice(eventKeys, func(i, j int) bool {
			if len(grouped[eventKeys[i]]) == len(grouped[eventKeys[j]]) {
				return eventKeys[i].expr < eventKeys[j].expr
			}
			return len(grouped[eventKeys[i]]) > len(grouped[eventKeys[j]])
		})
		fmt.Fprintf(&b, "  %s:\n", name)
		for _, k := range eventKeys {
			list := grouped[k]
			conf := list[0].confidence
			fmt.Fprintf(&b, "    Pattern: %s(%s)\n", k.name, k.expr)
			fmt.Fprintf(&b, "      Occurrences: %d\n", len(list))
			fmt.Fprintf(&b, "      Evidence:\n")
			for i := 0; i < min(len(list), 3); i++ {
				fmt.Fprintf(&b, "        - Line %d\n", list[i].eventIndex)
			}
			fmt.Fprintf(&b, "      Confidence: %s\n", conf)
		}
		b.WriteString("\n")
	}

	lengthCounts := map[string]int{}
	for _, inf := range inferences {
		if strings.TrimSpace(inf.lengthExpr) == "" {
			continue
		}
		lengthCounts[inf.lengthExpr]++
	}
	if len(lengthCounts) > 0 {
		b.WriteString("Length Pattern Summary:\n")
		type lengthRow struct {
			expr  string
			count int
		}
		rows := make([]lengthRow, 0, len(lengthCounts))
		for expr, count := range lengthCounts {
			rows = append(rows, lengthRow{expr: expr, count: count})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].count == rows[j].count {
				return rows[i].expr < rows[j].expr
			}
			return rows[i].count > rows[j].count
		})
		for _, row := range rows {
			fmt.Fprintf(&b, "  - %d times %s\n", row.count, row.expr)
		}
		b.WriteString("\n")
	}
	return b.String()
}

var (
	eventRefRE = regexp.MustCompile(`e\d+_a\d+`)
	lenRefRE   = regexp.MustCompile(`len:\d+`)
	hexRefRE   = regexp.MustCompile(`0x[0-9a-fA-F]+`)
)

func normalizeExprShape(expr string) string {
	labels := []string{"x", "y", "z", "w", "u", "v", "p", "q", "r", "s"}
	refOrder := map[string]int{}
	refSeq := 0
	shape := eventRefRE.ReplaceAllStringFunc(expr, func(match string) string {
		idx, ok := refOrder[match]
		if !ok {
			idx = refSeq
			refOrder[match] = idx
			refSeq++
		}
		label := labels[idx%len(labels)]
		return fmt.Sprintf("<bytes:%s>", label)
	})
	shape = lenRefRE.ReplaceAllString(shape, "len")
	shape = hexRefRE.ReplaceAllString(shape, "hex")
	return shape
}

func inferLengthShape(expr string, prev []valueRef) string {
	refLens := make(map[string]int, len(prev))
	for _, ref := range prev {
		refLens[formatRef(ref)] = len(ref.bytes)
	}

	shape := eventRefRE.ReplaceAllStringFunc(expr, func(match string) string {
		if n, ok := refLens[match]; ok {
			return fmt.Sprintf("<bytes:%d>", n)
		}
		return "<bytes:?>"
	})

	shape = regexp.MustCompile(`byte\(0x[0-9a-fA-F]+\)`).ReplaceAllString(shape, "<bytes:1>")
	shape = lenRefRE.ReplaceAllStringFunc(shape, func(match string) string {
		n := strings.TrimPrefix(match, "len:")
		return fmt.Sprintf("<bytes:%s>", n)
	})
	shape = hexRefRE.ReplaceAllStringFunc(shape, func(match string) string {
		h := strings.TrimPrefix(match, "0x")
		return fmt.Sprintf("<bytes:%d>", len(h)/2)
	})

	return shape
}

func plural(n int) string {
	// Small helper for pluralization in reports.
	if n == 1 {
		return ""
	}
	return "s"
}
