package cluster

import (
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// isSemanticJSONKey returns true for JSON keys whose integer values represent
// semantic status or exit codes and must be preserved verbatim (not replaced
// with <NUM>).
func isSemanticJSONKey(key string) bool {
	switch strings.ToLower(key) {
	case "exit_code", "exitcode", "status_code", "http_status", "code", "errno", "signal":
		return true
	}
	return false
}

// isBoundedJSONObject validates that s is a single RFC 8259 JSON object whose
// nesting depth does not exceed MaxJSONDepth and whose objects do not exceed
// MaxJSONKeys keys.
func isBoundedJSONObject(s string) bool {
	_, ok := parseBoundedJSONObject(s, false)
	return ok
}

// isBoundedNDJSON validates that s (after dropping any truncated trailing line)
// contains at least one non-empty line and that every non-empty line (up to
// MaxLinesPerPreview) is a bounded JSON object.
func isBoundedNDJSON(s string) bool {
	nonEmpty := 0
	valid := true
	forEachPreviewLine(s, func(rawLine string) bool {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			return true
		}
		if len(trimmed) > MaxLineBytes || trimmed[0] != '{' || !isBoundedJSONObject(trimmed) {
			valid = false
			return false
		}
		nonEmpty++
		return true
	})
	return valid && nonEmpty > 0
}

func forEachPreviewLine(s string, fn func(line string) bool) {
	lineIdx := 0
	pos := 0
	for pos <= len(s) && lineIdx < MaxLinesPerPreview {
		nl := strings.IndexByte(s[pos:], '\n')
		var rawLine string
		var hasNL bool
		if nl < 0 {
			rawLine = s[pos:]
			pos = len(s) + 1
		} else {
			rawLine = s[pos : pos+nl]
			pos += nl + 1
			hasNL = true
		}
		lineIdx++
		if !fn(rawLine) {
			return
		}
		if hasNL && pos == len(s) {
			break
		}
	}
}

func normalizeSingleJSON(s string, hm hostMatcher, maskIPs bool, streamPrefix string) (string, []MetricSlot, bool) {
	val, ok := parseBoundedJSONObject(s, true)
	if !ok {
		return "", nil, false
	}

	var slots []MetricSlot
	usedLabels := make(map[string]int, 16)
	var out strings.Builder
	out.Grow(len(s))
	renderJSONNode(&out, val, "", false, hm, maskIPs, streamPrefix, usedLabels, &slots)
	return out.String(), slots, true
}

type ndjsonLineEntry struct {
	template string
	slots    []MetricSlot
}

func normalizeNDJSON(s string, hm hostMatcher, maskIPs bool, streamPrefix string) (string, []MetricSlot, bool) {
	var entries []ndjsonLineEntry
	valid := true
	forEachPreviewLine(s, func(rawLine string) bool {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			return true
		}
		if len(trimmed) > MaxLineBytes {
			valid = false
			return false
		}
		tmpl, lineSlots, ok := normalizeSingleJSON(trimmed, hm, maskIPs, "")
		if !ok {
			valid = false
			return false
		}
		entries = append(entries, ndjsonLineEntry{template: tmpl, slots: lineSlots})
		return true
	})
	if !valid || len(entries) == 0 {
		return "", nil, false
	}

	// Sort normalized line templates lexicographically to eliminate ordering
	// noise (e.g. docker ps container start order).
	slices.SortFunc(entries, func(a, b ndjsonLineEntry) int {
		return strings.Compare(a.template, b.template)
	})

	var out strings.Builder
	var slots []MetricSlot
	usedLabels := make(map[string]int, 16)

	// Record total NDJSON line count as a deterministic metric slot.
	lineCountLabel := "$ndjson.lines"
	if streamPrefix != "" {
		lineCountLabel = streamPrefix + lineCountLabel
	}
	slots = append(slots, MetricSlot{
		Label: dedupSanitizedLabel(lineCountLabel, usedLabels),
		Value: float64(len(entries)),
	})

	groupIdx := 0
	for i := 0; i < len(entries); {
		j := i + 1
		for j < len(entries) && entries[j].template == entries[i].template {
			j++
		}
		count := j - i
		if groupIdx > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(entries[i].template)
		if count > 1 {
			out.WriteString(" (x")
			out.WriteString(strconv.Itoa(count))
			out.WriteByte(')')
		}
		// Attach slots from the representative unique line (when count == 1) in deterministic order.
		if count == 1 && len(slots) < MaxSlotsPerTask {
			prefix := streamPrefix
			if len(entries) > 1 {
				prefix += "[" + strconv.Itoa(groupIdx) + "]."
			}
			for _, sl := range entries[i].slots {
				if len(slots) >= MaxSlotsPerTask {
					break
				}
				slots = append(slots, MetricSlot{
					Label: dedupSanitizedLabel(prefix+sl.Label, usedLabels),
					Unit:  sl.Unit,
					Value: sl.Value,
				})
			}
		}
		groupIdx++
		i = j
	}

	return out.String(), slots, true
}

type jsonKind uint8

const (
	jsonNull jsonKind = iota
	jsonBool
	jsonNumber
	jsonString
	jsonArray
	jsonObject
)

type jsonKV struct {
	key string
	val jsonNode
}

type jsonNode struct {
	kind     jsonKind
	raw      string     // literal number or bool
	str      string     // unescaped string
	items    []jsonNode // up to MaxJSONArrayItems
	totalLen int        // total elements in array (may exceed len(items))
	fields   []jsonKV   // object key-value pairs
}

// parseBoundedJSONObject decodes a single RFC 8259 JSON object using the
// standard library streaming token decoder while strictly enforcing
// MaxJSONDepth, MaxJSONKeys, MaxJSONArrayItems, and rejecting trailing tokens.
// When keep is false, nodes are validated without retaining an AST.
func parseBoundedJSONObject(s string, keep bool) (jsonNode, bool) {
	if s == "" {
		return jsonNode{}, false
	}
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil {
		return jsonNode{}, false
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return jsonNode{}, false
	}
	node, ok := decodeJSONObject(d, 1, keep)
	if !ok {
		return jsonNode{}, false
	}
	if _, err := d.Token(); err != io.EOF {
		return jsonNode{}, false
	}
	return node, true
}

func decodeJSONValue(d *json.Decoder, depth int, keep bool) (jsonNode, bool) {
	tok, err := d.Token()
	if err != nil {
		return jsonNode{}, false
	}
	switch v := tok.(type) {
	case json.Delim:
		if depth >= MaxJSONDepth {
			return jsonNode{}, false
		}
		switch v {
		case '{':
			return decodeJSONObject(d, depth+1, keep)
		case '[':
			return decodeJSONArray(d, depth+1, keep)
		default:
			return jsonNode{}, false
		}
	case nil:
		if keep {
			return jsonNode{kind: jsonNull, raw: "null"}, true
		}
		return jsonNode{}, true
	case bool:
		if keep {
			if v {
				return jsonNode{kind: jsonBool, raw: "true"}, true
			}
			return jsonNode{kind: jsonBool, raw: "false"}, true
		}
		return jsonNode{}, true
	case json.Number:
		if keep {
			return jsonNode{kind: jsonNumber, raw: string(v)}, true
		}
		return jsonNode{}, true
	case string:
		if keep {
			return jsonNode{kind: jsonString, str: v}, true
		}
		return jsonNode{}, true
	default:
		return jsonNode{}, false
	}
}

func decodeJSONObject(d *json.Decoder, depth int, keep bool) (jsonNode, bool) {
	keys := 0
	var fields []jsonKV
	for d.More() {
		keyTok, err := d.Token()
		if err != nil {
			return jsonNode{}, false
		}
		key, ok := keyTok.(string)
		if !ok {
			return jsonNode{}, false
		}
		keys++
		if keys > MaxJSONKeys {
			return jsonNode{}, false
		}
		val, ok := decodeJSONValue(d, depth, keep)
		if !ok {
			return jsonNode{}, false
		}
		if keep {
			fields = append(fields, jsonKV{key: key, val: val})
		}
	}
	endTok, err := d.Token()
	if err != nil || endTok != json.Delim('}') {
		return jsonNode{}, false
	}
	if keep {
		return jsonNode{kind: jsonObject, fields: fields}, true
	}
	return jsonNode{}, true
}

func decodeJSONArray(d *json.Decoder, depth int, keep bool) (jsonNode, bool) {
	var items []jsonNode
	total := 0
	for d.More() {
		keepItem := keep && len(items) < MaxJSONArrayItems
		val, ok := decodeJSONValue(d, depth, keepItem)
		if !ok {
			return jsonNode{}, false
		}
		if keepItem {
			items = append(items, val)
		}
		total++
	}
	endTok, err := d.Token()
	if err != nil || endTok != json.Delim(']') {
		return jsonNode{}, false
	}
	if keep {
		return jsonNode{kind: jsonArray, items: items, totalLen: total}, true
	}
	return jsonNode{}, true
}

func renderJSONNode(
	out *strings.Builder,
	node jsonNode,
	path string,
	semanticKey bool,
	hm hostMatcher,
	maskIPs bool,
	streamPrefix string,
	usedLabels map[string]int,
	slots *[]MetricSlot,
) {
	switch node.kind {
	case jsonNull:
		out.WriteString("null")
	case jsonBool:
		out.WriteString(node.raw)
	case jsonNumber:
		if semanticKey && !strings.ContainsAny(node.raw, ".eE") {
			if _, err := strconv.ParseInt(node.raw, 10, 64); err == nil {
				out.WriteString(node.raw)
				return
			}
		}
		out.WriteString("<NUM>")
		if len(*slots) < MaxSlotsPerTask {
			v, err := strconv.ParseFloat(node.raw, 64)
			if err == nil && isFiniteFloat(v) {
				lbl := path
				if lbl == "" {
					lbl = "value"
				}
				if streamPrefix != "" {
					lbl = streamPrefix + lbl
				}
				*slots = append(*slots, MetricSlot{
					Label: dedupSanitizedLabel(lbl, usedLabels),
					Value: v,
				})
			}
		}
	case jsonString:
		normStr, strSlots := normalizeJSONStringValue(node.str, semanticKey, hm, maskIPs)
		writeJSONQuoted(out, normStr)
		if len(strSlots) > 0 && len(*slots) < MaxSlotsPerTask {
			for idx, rs := range strSlots {
				if len(*slots) >= MaxSlotsPerTask {
					break
				}
				if !isFiniteFloat(rs.value) {
					continue
				}
				lbl := path
				if lbl == "" {
					lbl = "value"
				}
				if len(strSlots) > 1 {
					lbl += "[" + strconv.Itoa(idx) + "]"
				}
				if streamPrefix != "" {
					lbl = streamPrefix + lbl
				}
				*slots = append(*slots, MetricSlot{
					Label: dedupSanitizedLabel(lbl, usedLabels),
					Unit:  SanitizeLabel(rs.unit),
					Value: rs.value,
				})
			}
		}
	case jsonObject:
		// Sort keys lexicographically (stable deduplication: last value wins for duplicate keys).
		sorted := dedupAndSortFields(node.fields)
		out.WriteByte('{')
		for idx, kv := range sorted {
			if idx > 0 {
				out.WriteByte(',')
			}
			writeJSONQuoted(out, kv.key)
			out.WriteByte(':')
			childPath := kv.key
			if path != "" {
				childPath = path + "." + kv.key
			}
			renderJSONNode(out, kv.val, childPath, isSemanticJSONKey(kv.key), hm, maskIPs, streamPrefix, usedLabels, slots)
		}
		out.WriteByte('}')
	case jsonArray:
		if len(node.items) == 0 {
			out.WriteString("[]")
			return
		}
		// Render each scanned element into a temporary template to check homogeneity.
		elemTemplates := make([]string, len(node.items))
		elemSlots := make([][]MetricSlot, len(node.items))
		homogeneous := true
		for idx, item := range node.items {
			var eb strings.Builder
			var es []MetricSlot
			eUsed := make(map[string]int, 4)
			elemPath := path + "[" + strconv.Itoa(idx) + "]"
			renderJSONNode(&eb, item, elemPath, false, hm, maskIPs, streamPrefix, eUsed, &es)
			elemTemplates[idx] = eb.String()
			elemSlots[idx] = es
			if idx > 0 && elemTemplates[idx] != elemTemplates[0] {
				homogeneous = false
			}
		}

		// Always record path.$len for non-empty arrays (for homogeneous folding & length drift).
		if len(*slots) < MaxSlotsPerTask {
			lenLabel := "$len"
			if path != "" {
				lenLabel = path + ".$len"
			}
			if streamPrefix != "" {
				lenLabel = streamPrefix + lenLabel
			}
			*slots = append(*slots, MetricSlot{
				Label: dedupSanitizedLabel(lenLabel, usedLabels),
				Value: float64(node.totalLen),
			})
		}

		if homogeneous {
			out.WriteByte('[')
			out.WriteString(elemTemplates[0])
			out.WriteString(",...]")
			return
		}

		out.WriteByte('[')
		for idx, tmpl := range elemTemplates {
			if idx > 0 {
				out.WriteByte(',')
			}
			out.WriteString(tmpl)
			for _, sl := range elemSlots[idx] {
				if len(*slots) >= MaxSlotsPerTask {
					break
				}
				sl.Label = dedupSanitizedLabel(sl.Label, usedLabels)
				*slots = append(*slots, sl)
			}
		}
		if node.totalLen > len(node.items) {
			out.WriteString(",...")
		}
		out.WriteByte(']')
	}
}

func dedupAndSortFields(fields []jsonKV) []jsonKV {
	if len(fields) <= 1 {
		return fields
	}
	// Keep last occurrence of duplicate keys while preserving deterministic order.
	cp := slices.Clone(fields)
	slices.SortStableFunc(cp, func(a, b jsonKV) int {
		return strings.Compare(a.key, b.key)
	})
	out := cp[:0]
	for i := 0; i < len(cp); i++ {
		if i+1 < len(cp) && cp[i].key == cp[i+1].key {
			continue
		}
		out = append(out, cp[i])
	}
	return out
}

func normalizeJSONStringValue(s string, semanticKey bool, hm hostMatcher, maskIPs bool) (string, []rawLineSlot) {
	if s == "" {
		return "", nil
	}
	// Preserve short semantic integer strings under semantic keys (e.g. "http_status": "500").
	if semanticKey && len(s) <= 6 {
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return s, nil
		}
	}
	// Short low-entropy status words (e.g. "running", "active", "healthy", "INFO", "ERROR").
	if isShortStatusWord(s) && hm.match(s, 0) == 0 {
		return s, nil
	}
	if len(s) > MaxLineBytes {
		s = truncateUTF8Bytes(s, MaxLineBytes)
	}
	var b strings.Builder
	var slots []rawLineSlot
	// Normalize multi-line JSON string values (e.g. stack traces) line-by-line.
	if strings.ContainsRune(s, '\n') {
		b.Grow(len(s))
		lines := strings.Split(s, "\n")
		limit := min(len(lines), MaxLinesPerPreview)
		for idx := 0; idx < limit; idx++ {
			if idx > 0 {
				b.WriteByte('\n')
			}
			line := strings.TrimRight(lines[idx], "\r")
			scanLine(&b, collapseWhitespace(line), hm, maskIPs, true, &slots)
		}
		return b.String(), slots
	}
	collapsed := collapseWhitespace(s)
	b.Grow(len(collapsed))
	scanLine(&b, collapsed, hm, maskIPs, true, &slots)
	return b.String(), slots
}

func isShortStatusWord(s string) bool {
	if len(s) == 0 || len(s) > 24 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func writeJSONQuoted(out *strings.Builder, s string) {
	out.WriteByte('"')
	for i := 0; i < len(s); {
		b := s[i]
		if b < utf8.RuneSelf {
			switch b {
			case '"':
				out.WriteString(`\"`)
			case '\\':
				out.WriteString(`\\`)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if b < 0x20 {
					out.WriteString(`\u00`)
					const hex = "0123456789abcdef"
					out.WriteByte(hex[b>>4])
					out.WriteByte(hex[b&0x0f])
				} else {
					out.WriteByte(b)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			out.WriteString("\uFFFD")
			i++
			continue
		}
		out.WriteString(s[i : i+size])
		i += size
	}
	out.WriteByte('"')
}
