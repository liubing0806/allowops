package cluster

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
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
	p := jsonParser{s: s}
	p.skipWS()
	if p.pos >= len(p.s) || p.s[p.pos] != '{' {
		return false
	}
	if !p.validateValue(0) {
		return false
	}
	p.skipWS()
	return p.pos == len(p.s)
}

// isBoundedNDJSON validates that s (after dropping any truncated trailing line)
// contains at least one non-empty line and that every non-empty line (up to
// MaxLinesPerPreview) is a bounded JSON object.
func isBoundedNDJSON(s string) bool {
	nonEmpty := 0
	lineIdx := 0
	pos := 0
	for pos <= len(s) {
		if lineIdx >= MaxLinesPerPreview {
			break
		}
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
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			if hasNL && pos == len(s) {
				break
			}
			continue
		}
		if len(trimmed) > MaxLineBytes || trimmed[0] != '{' || !isBoundedJSONObject(trimmed) {
			return false
		}
		nonEmpty++
		if hasNL && pos == len(s) {
			break
		}
	}
	return nonEmpty > 0
}

func normalizeSingleJSON(s string, hm hostMatcher, maskIPs bool, streamPrefix string) (string, []MetricSlot, bool) {
	p := jsonParser{s: s}
	p.skipWS()
	if p.pos >= len(p.s) || p.s[p.pos] != '{' {
		return "", nil, false
	}
	val, ok := p.parseValue(0)
	if !ok {
		return "", nil, false
	}
	p.skipWS()
	if p.pos != len(p.s) {
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
	lineIdx := 0
	pos := 0
	for pos <= len(s) {
		if lineIdx >= MaxLinesPerPreview {
			break
		}
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
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			if hasNL && pos == len(s) {
				break
			}
			continue
		}
		if len(trimmed) > MaxLineBytes {
			return "", nil, false
		}
		tmpl, lineSlots, ok := normalizeSingleJSON(trimmed, hm, maskIPs, "")
		if !ok {
			return "", nil, false
		}
		entries = append(entries, ndjsonLineEntry{template: tmpl, slots: lineSlots})
		if hasNL && pos == len(s) {
			break
		}
	}
	if len(entries) == 0 {
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
		Label:     dedupSanitizedLabel(lineCountLabel, usedLabels),
		Unit:      "",
		Value:     float64(len(entries)),
		IsInteger: true,
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
					Label:     dedupSanitizedLabel(prefix+sl.Label, usedLabels),
					Unit:      sl.Unit,
					Value:     sl.Value,
					IsInteger: sl.IsInteger,
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

type jsonParser struct {
	s   string
	pos int
}

func (p *jsonParser) skipWS() {
	for p.pos < len(p.s) {
		switch p.s[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *jsonParser) validateValue(depth int) bool {
	p.skipWS()
	if p.pos >= len(p.s) {
		return false
	}
	switch p.s[p.pos] {
	case '{':
		if depth >= MaxJSONDepth {
			return false
		}
		return p.validateObject(depth + 1)
	case '[':
		if depth >= MaxJSONDepth {
			return false
		}
		return p.validateArray(depth + 1)
	case '"':
		_, ok := p.parseString()
		return ok
	case 't':
		if strings.HasPrefix(p.s[p.pos:], "true") {
			p.pos += 4
			return true
		}
		return false
	case 'f':
		if strings.HasPrefix(p.s[p.pos:], "false") {
			p.pos += 5
			return true
		}
		return false
	case 'n':
		if strings.HasPrefix(p.s[p.pos:], "null") {
			p.pos += 4
			return true
		}
		return false
	default:
		_, ok := p.scanNumber()
		return ok
	}
}

func (p *jsonParser) validateObject(depth int) bool {
	p.pos++ // skip '{'
	p.skipWS()
	if p.pos < len(p.s) && p.s[p.pos] == '}' {
		p.pos++
		return true
	}
	keys := 0
	for {
		p.skipWS()
		if p.pos >= len(p.s) || p.s[p.pos] != '"' {
			return false
		}
		if _, ok := p.parseString(); !ok {
			return false
		}
		keys++
		if keys > MaxJSONKeys {
			return false
		}
		p.skipWS()
		if p.pos >= len(p.s) || p.s[p.pos] != ':' {
			return false
		}
		p.pos++
		if !p.validateValue(depth) {
			return false
		}
		p.skipWS()
		if p.pos >= len(p.s) {
			return false
		}
		if p.s[p.pos] == '}' {
			p.pos++
			return true
		}
		if p.s[p.pos] != ',' {
			return false
		}
		p.pos++
	}
}

func (p *jsonParser) validateArray(depth int) bool {
	p.pos++ // skip '['
	p.skipWS()
	if p.pos < len(p.s) && p.s[p.pos] == ']' {
		p.pos++
		return true
	}
	for {
		if !p.validateValue(depth) {
			return false
		}
		p.skipWS()
		if p.pos >= len(p.s) {
			return false
		}
		if p.s[p.pos] == ']' {
			p.pos++
			return true
		}
		if p.s[p.pos] != ',' {
			return false
		}
		p.pos++
	}
}

func (p *jsonParser) parseValue(depth int) (jsonNode, bool) {
	p.skipWS()
	if p.pos >= len(p.s) {
		return jsonNode{}, false
	}
	switch p.s[p.pos] {
	case '{':
		if depth >= MaxJSONDepth {
			return jsonNode{}, false
		}
		return p.parseObject(depth + 1)
	case '[':
		if depth >= MaxJSONDepth {
			return jsonNode{}, false
		}
		return p.parseArray(depth + 1)
	case '"':
		str, ok := p.parseString()
		if !ok {
			return jsonNode{}, false
		}
		return jsonNode{kind: jsonString, str: str}, true
	case 't':
		if strings.HasPrefix(p.s[p.pos:], "true") {
			p.pos += 4
			return jsonNode{kind: jsonBool, raw: "true"}, true
		}
		return jsonNode{}, false
	case 'f':
		if strings.HasPrefix(p.s[p.pos:], "false") {
			p.pos += 5
			return jsonNode{kind: jsonBool, raw: "false"}, true
		}
		return jsonNode{}, false
	case 'n':
		if strings.HasPrefix(p.s[p.pos:], "null") {
			p.pos += 4
			return jsonNode{kind: jsonNull, raw: "null"}, true
		}
		return jsonNode{}, false
	default:
		raw, ok := p.scanNumber()
		if !ok {
			return jsonNode{}, false
		}
		return jsonNode{kind: jsonNumber, raw: raw}, true
	}
}

func (p *jsonParser) parseObject(depth int) (jsonNode, bool) {
	p.pos++ // skip '{'
	p.skipWS()
	if p.pos < len(p.s) && p.s[p.pos] == '}' {
		p.pos++
		return jsonNode{kind: jsonObject}, true
	}
	var fields []jsonKV
	for {
		p.skipWS()
		if p.pos >= len(p.s) || p.s[p.pos] != '"' {
			return jsonNode{}, false
		}
		key, ok := p.parseString()
		if !ok {
			return jsonNode{}, false
		}
		if len(fields) >= MaxJSONKeys {
			return jsonNode{}, false
		}
		p.skipWS()
		if p.pos >= len(p.s) || p.s[p.pos] != ':' {
			return jsonNode{}, false
		}
		p.pos++
		val, ok := p.parseValue(depth)
		if !ok {
			return jsonNode{}, false
		}
		fields = append(fields, jsonKV{key: key, val: val})
		p.skipWS()
		if p.pos >= len(p.s) {
			return jsonNode{}, false
		}
		if p.s[p.pos] == '}' {
			p.pos++
			return jsonNode{kind: jsonObject, fields: fields}, true
		}
		if p.s[p.pos] != ',' {
			return jsonNode{}, false
		}
		p.pos++
	}
}

func (p *jsonParser) parseArray(depth int) (jsonNode, bool) {
	p.pos++ // skip '['
	p.skipWS()
	if p.pos < len(p.s) && p.s[p.pos] == ']' {
		p.pos++
		return jsonNode{kind: jsonArray}, true
	}
	var items []jsonNode
	total := 0
	for {
		if len(items) < MaxJSONArrayItems {
			val, ok := p.parseValue(depth)
			if !ok {
				return jsonNode{}, false
			}
			items = append(items, val)
		} else {
			if !p.validateValue(depth) {
				return jsonNode{}, false
			}
		}
		total++
		p.skipWS()
		if p.pos >= len(p.s) {
			return jsonNode{}, false
		}
		if p.s[p.pos] == ']' {
			p.pos++
			return jsonNode{kind: jsonArray, items: items, totalLen: total}, true
		}
		if p.s[p.pos] != ',' {
			return jsonNode{}, false
		}
		p.pos++
	}
}

func (p *jsonParser) parseString() (string, bool) {
	if p.pos >= len(p.s) || p.s[p.pos] != '"' {
		return "", false
	}
	p.pos++
	start := p.pos
	hasEscape := false
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == '"' {
			if !hasEscape {
				out := p.s[start:p.pos]
				p.pos++
				return out, true
			}
			break
		}
		if c < 0x20 {
			return "", false
		}
		if c == '\\' {
			hasEscape = true
			p.pos += 2
			if p.pos > len(p.s) {
				return "", false
			}
			continue
		}
		p.pos++
	}
	if !hasEscape {
		return "", false
	}
	// Slow path with escape decoding.
	p.pos = start
	var b strings.Builder
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c == '"' {
			p.pos++
			return b.String(), true
		}
		if c < 0x20 {
			return "", false
		}
		if c != '\\' {
			b.WriteByte(c)
			p.pos++
			continue
		}
		p.pos++
		if p.pos >= len(p.s) {
			return "", false
		}
		esc := p.s[p.pos]
		p.pos++
		switch esc {
		case '"', '\\', '/':
			b.WriteByte(esc)
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r1, ok := p.parseHex4()
			if !ok {
				return "", false
			}
			if utf16.IsSurrogate(r1) && p.pos+6 <= len(p.s) && p.s[p.pos] == '\\' && p.s[p.pos+1] == 'u' {
				p.pos += 2
				r2, ok := p.parseHex4()
				if !ok {
					return "", false
				}
				b.WriteRune(utf16.DecodeRune(r1, r2))
			} else {
				b.WriteRune(r1)
			}
		default:
			return "", false
		}
	}
	return "", false
}

func (p *jsonParser) parseHex4() (rune, bool) {
	if p.pos+4 > len(p.s) {
		return 0, false
	}
	var val rune
	for i := 0; i < 4; i++ {
		c := p.s[p.pos+i]
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			val |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			val |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	p.pos += 4
	return val, true
}

func (p *jsonParser) scanNumber() (string, bool) {
	start := p.pos
	if p.pos < len(p.s) && p.s[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.s) {
		return "", false
	}
	if p.s[p.pos] == '0' {
		p.pos++
	} else if p.s[p.pos] >= '1' && p.s[p.pos] <= '9' {
		p.pos++
		for p.pos < len(p.s) && isDigit(p.s[p.pos]) {
			p.pos++
		}
	} else {
		return "", false
	}
	if p.pos < len(p.s) && p.s[p.pos] == '.' {
		p.pos++
		dStart := p.pos
		for p.pos < len(p.s) && isDigit(p.s[p.pos]) {
			p.pos++
		}
		if p.pos == dStart {
			return "", false
		}
	}
	if p.pos < len(p.s) && (p.s[p.pos] == 'e' || p.s[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.s) && (p.s[p.pos] == '+' || p.s[p.pos] == '-') {
			p.pos++
		}
		dStart := p.pos
		for p.pos < len(p.s) && isDigit(p.s[p.pos]) {
			p.pos++
		}
		if p.pos == dStart {
			return "", false
		}
	}
	return p.s[start:p.pos], true
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
		isInt := !strings.ContainsAny(node.raw, ".eE")
		if semanticKey && isInt {
			if _, err := strconv.ParseInt(node.raw, 10, 64); err == nil {
				out.WriteString(node.raw)
				return
			}
		}
		out.WriteString("<NUM>")
		if len(*slots) < MaxSlotsPerTask {
			v, err := strconv.ParseFloat(node.raw, 64)
			if err == nil && isFiniteFloat(v) {
				intOK := isInt
				if intOK {
					if _, iErr := strconv.ParseInt(node.raw, 10, 64); iErr != nil {
						intOK = false
					}
				}
				lbl := path
				if lbl == "" {
					lbl = "value"
				}
				if streamPrefix != "" {
					lbl = streamPrefix + lbl
				}
				*slots = append(*slots, MetricSlot{
					Label:     dedupSanitizedLabel(lbl, usedLabels),
					Unit:      "",
					Value:     v,
					IsInteger: intOK,
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
					Label:     dedupSanitizedLabel(lbl, usedLabels),
					Unit:      SanitizeLabel(rs.unit),
					Value:     rs.value,
					IsInteger: rs.isInteger,
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
				Label:     dedupSanitizedLabel(lenLabel, usedLabels),
				Unit:      "",
				Value:     float64(node.totalLen),
				IsInteger: true,
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
	cp := make([]jsonKV, len(fields))
	copy(cp, fields)
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
	// Normalize multi-line JSON string values (e.g. stack traces) line-by-line.
	if strings.ContainsRune(s, '\n') {
		var b strings.Builder
		var allSlots []rawLineSlot
		lines := strings.Split(s, "\n")
		limit := min(len(lines), MaxLinesPerPreview)
		for idx := 0; idx < limit; idx++ {
			if idx > 0 {
				b.WriteByte('\n')
			}
			line := strings.TrimRight(lines[idx], "\r")
			collapsed := collapseWhitespace(line)
			norm, sl := scanLine(collapsed, hm, maskIPs)
			b.WriteString(norm)
			allSlots = append(allSlots, sl...)
		}
		return b.String(), allSlots
	}
	collapsed := collapseWhitespace(s)
	return scanLine(collapsed, hm, maskIPs)
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
