package cluster

import (
	"crypto/sha256"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NormalizeOptions configures preview normalization.
type NormalizeOptions struct {
	// Hostname of the task being normalized; matched on non-alphanumeric
	// boundaries (along with eligible short hostnames) and masked to <HOST>.
	Hostname string
	// MaskIPs controls whether IPv4/IPv6 addresses (and optional :port / /cidr)
	// are replaced with <IP>/<IP_PORT>. Defaults to true via DefaultNormalizeOptions.
	MaskIPs bool
	// Mode forces a specific normalization mode (text, json, ndjson).
	// When PreviewModeAuto (""), NormalizePreview detects mode for the single preview.
	Mode PreviewMode
	// Truncated indicates whether the preview was truncated from a larger stream
	// (e.g. totalSize > len(preview)). When true and the preview contains at least
	// one '\n', the incomplete trailing line is dropped before normalization.
	Truncated bool
	// StreamPrefix is optionally prepended to extracted numeric slot labels (e.g. "stderr.").
	StreamPrefix string
}

// DefaultNormalizeOptions returns NormalizeOptions with MaskIPs enabled.
func DefaultNormalizeOptions(hostname string) NormalizeOptions {
	return NormalizeOptions{
		Hostname: hostname,
		MaskIPs:  true,
	}
}

// MetricSlot is a single finite numeric observation extracted during normalization.
type MetricSlot struct {
	Label string  // sanitized valid UTF-8, <= MaxLabelBytes
	Unit  string  // sanitized valid UTF-8, <= MaxLabelBytes ("%", "bytes", "ms", or "")
	Value float64 // strictly finite (!NaN && !Inf)
}

// NormalizeResult holds the normalized output template, its SHA-256 digest,
// selected mode, and extracted finite numeric slots.
type NormalizeResult struct {
	Template  string
	Hash      [32]byte
	Mode      PreviewMode
	Slots     []MetricSlot
	Truncated bool
}

// PreviewSample is a minimal preview descriptor used for job-level unified
// JSON/NDJSON/text mode detection.
type PreviewSample struct {
	Data      []byte
	TotalSize uint64
}

// DetectStreamMode performs an O(N) job-level check over all non-empty previews
// to select a single unified normalization mode across the fleet, preventing
// false cluster splits when some hosts cross the 4 KiB JSON truncation boundary.
//
// Rules:
//  1. If there are no non-empty previews, returns PreviewModeText.
//  2. If ALL non-empty previews are untruncated, start with '{' after trimming
//     whitespace, and parse as a single bounded JSON object (within MaxJSONDepth
//     and MaxJSONKeys), returns PreviewModeJSON.
//  3. Else if ALL non-empty previews (after dropping any truncated trailing line)
//     consist exclusively of bounded JSON object lines (at least 1 non-empty line),
//     returns PreviewModeNDJSON.
//  4. Otherwise returns PreviewModeText.
func DetectStreamMode(samples []PreviewSample) PreviewMode {
	hasNonEmpty := false
	allSingleJSON := true
	allNDJSON := true

	for _, s := range samples {
		if len(s.Data) == 0 {
			continue
		}
		capped := capPreviewBytes(s.Data)
		first, ok := firstNonWhitespaceByte(capped)
		if !ok {
			continue
		}
		hasNonEmpty = true
		if first != '{' {
			return PreviewModeText
		}

		truncated := s.TotalSize > uint64(len(s.Data)) || len(s.Data) > MaxPreviewBytesPerStream
		trimmed := strings.TrimSpace(toValidUTF8(capped))
		if trimmed == "" {
			continue
		}

		if allSingleJSON && (truncated || trimmed[0] != '{' || !isBoundedJSONObject(trimmed)) {
			allSingleJSON = false
		}
		if allNDJSON && !isBoundedNDJSON(preparePreviewText(capped, truncated)) {
			allNDJSON = false
		}
		if !allSingleJSON && !allNDJSON {
			return PreviewModeText
		}
	}

	if !hasNonEmpty {
		return PreviewModeText
	}
	if allSingleJSON {
		return PreviewModeJSON
	}
	if allNDJSON {
		return PreviewModeNDJSON
	}
	return PreviewModeText
}

func firstNonWhitespaceByte(b []byte) (byte, bool) {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return c, true
		}
	}
	return 0, false
}

// NormalizePreview normalizes a single stream preview into a deterministic template
// and extracts bounded finite numeric slots.
func NormalizePreview(raw []byte, opts NormalizeOptions) NormalizeResult {
	wasTruncated := opts.Truncated || len(raw) > MaxPreviewBytesPerStream
	capped := capPreviewBytes(raw)
	if len(capped) == 0 {
		mode := opts.Mode
		if mode == PreviewModeAuto {
			mode = PreviewModeText
		}
		return NormalizeResult{
			Hash:      sha256.Sum256(nil),
			Mode:      mode,
			Truncated: wasTruncated,
		}
	}

	mode := opts.Mode
	if mode == PreviewModeAuto {
		mode = PreviewModeText
		if first, ok := firstNonWhitespaceByte(capped); ok && first == '{' {
			trimmed := strings.TrimSpace(toValidUTF8(capped))
			if !wasTruncated && trimmed != "" && trimmed[0] == '{' && isBoundedJSONObject(trimmed) {
				mode = PreviewModeJSON
			} else if trimmed != "" && isBoundedNDJSON(preparePreviewText(capped, wasTruncated)) {
				mode = PreviewModeNDJSON
			}
		}
	}

	hm := newHostMatcher(opts.Hostname)
	switch mode {
	case PreviewModeJSON:
		text := strings.TrimSpace(toValidUTF8(capped))
		if tmpl, slots, ok := normalizeSingleJSON(text, hm, opts.MaskIPs, opts.StreamPrefix); ok {
			return NormalizeResult{
				Template:  tmpl,
				Hash:      sha256.Sum256([]byte(tmpl)),
				Mode:      PreviewModeJSON,
				Slots:     slots,
				Truncated: wasTruncated,
			}
		}
		mode = PreviewModeText
	case PreviewModeNDJSON:
		prepared := preparePreviewText(capped, wasTruncated)
		if tmpl, slots, lineTrunc, ok := normalizeNDJSON(prepared, hm, opts.MaskIPs, opts.StreamPrefix); ok {
			return NormalizeResult{
				Template:  tmpl,
				Hash:      sha256.Sum256([]byte(tmpl)),
				Mode:      PreviewModeNDJSON,
				Slots:     slots,
				Truncated: wasTruncated || lineTrunc,
			}
		}
		mode = PreviewModeText
	}

	prepared := preparePreviewText(capped, wasTruncated)
	tmpl, slots, lineTrunc := normalizeTextPreview(prepared, hm, opts.MaskIPs, opts.StreamPrefix)
	return NormalizeResult{
		Template:  tmpl,
		Hash:      sha256.Sum256([]byte(tmpl)),
		Mode:      mode,
		Slots:     slots,
		Truncated: wasTruncated || lineTrunc,
	}
}

// SanitizeLabel strips control characters (< 0x20 and 0x7f), collapses
// consecutive whitespace to a single space, ensures valid UTF-8, and truncates
// to at most MaxLabelBytes on a valid rune boundary.
func SanitizeLabel(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= MaxLabelBytes && isCleanASCIILabel(s) {
		return s
	}

	var b strings.Builder
	b.Grow(min(len(s), MaxLabelBytes))
	inSpace := true // trims leading whitespace
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !inSpace {
				if b.Len()+1 > MaxLabelBytes {
					break
				}
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+size > MaxLabelBytes {
			break
		}
		b.WriteRune(r)
		inSpace = false
	}
	return strings.TrimRight(b.String(), " ")
}

func isCleanASCIILabel(s string) bool {
	if s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			return false
		}
		if c == ' ' {
			if prevSpace {
				return false
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
	}
	return true
}

func isFiniteFloat(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func capPreviewBytes(raw []byte) []byte {
	if len(raw) <= MaxPreviewBytesPerStream {
		return raw
	}
	b := raw[:MaxPreviewBytesPerStream]
	for len(b) > 0 && len(b) > MaxPreviewBytesPerStream-4 && !utf8.Valid(b) {
		if b[len(b)-1] < 0x80 {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}

func toValidUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// truncateUTF8Bytes truncates s to at most maxBytes on a valid UTF-8 boundary.
func truncateUTF8Bytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 0 {
		return ""
	}
	n := maxBytes
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// preparePreviewText converts capped preview bytes to valid UTF-8 and drops
// the trailing incomplete line when truncated and at least one '\n' exists.
func preparePreviewText(capped []byte, truncated bool) string {
	s := toValidUTF8(capped)
	if truncated {
		if idx := strings.LastIndexByte(s, '\n'); idx >= 0 {
			s = s[:idx]
		}
	}
	return s
}

// hostMatcher holds the full hostname and optional eligible short hostname.
type hostMatcher struct {
	full      string
	short     string
	firstByte byte
}

func newHostMatcher(hostname string) hostMatcher {
	if !utf8.ValidString(hostname) {
		hostname = strings.ToValidUTF8(hostname, "")
	}
	h := strings.TrimSpace(hostname)
	if h == "" {
		return hostMatcher{}
	}
	m := hostMatcher{full: h, firstByte: h[0]}
	if dot := strings.IndexByte(h, '.'); dot >= 0 {
		cand := h[:dot]
		if len(cand) >= 3 && strings.ContainsAny(cand, "-0123456789") {
			m.short = cand
		}
	}
	return m
}

func (m hostMatcher) match(line string, i int) int {
	if m.full == "" || line[i] != m.firstByte || !utf8.RuneStart(line[i]) {
		return 0
	}
	if i > 0 && isAlphaNum(line[i-1]) {
		return 0
	}
	for _, cand := range [2]string{m.full, m.short} {
		if cand == "" || len(cand) > len(line)-i || line[i:i+len(cand)] != cand {
			continue
		}
		end := i + len(cand)
		if end == len(line) || (!isAlphaNum(line[end]) && utf8.RuneStart(line[end])) {
			return len(cand)
		}
	}
	return 0
}

type tableHeaderInfo struct {
	cols        []string
	hasLeadingW bool
}

type byteSpan struct {
	start int
	end   int
}

type rawLineSlot struct {
	start int // byte offset in collapsed line
	end   int
	unit  string
	value float64
}

func normalizeTextPreview(text string, hm hostMatcher, maskIPs bool, streamPrefix string) (string, []MetricSlot, bool) {
	if text == "" {
		return "", nil, false
	}

	line0LeadingWS := text[0] == ' ' || text[0] == '\t'
	collapsedText, truncated := collapsePreviewLines(text)

	var out strings.Builder
	out.Grow(len(collapsedText))
	var slots []MetricSlot
	var lineSlots []rawLineSlot
	var tokens []byteSpan
	var usedLabels map[string]int
	var header *tableHeaderInfo

	lineIdx := 0
	pos := 0
	for pos <= len(collapsedText) {
		if lineIdx >= MaxLinesPerPreview {
			truncated = true
			break
		}
		nl := strings.IndexByte(collapsedText[pos:], '\n')
		var collapsed string
		var hasNL bool
		if nl < 0 {
			collapsed = collapsedText[pos:]
			pos = len(collapsedText) + 1
		} else {
			collapsed = collapsedText[pos : pos+nl]
			pos += nl + 1
			hasNL = true
		}
		if len(collapsed) > MaxLineBytes {
			collapsed = truncateUTF8Bytes(collapsed, MaxLineBytes)
			truncated = true
		}

		if lineIdx > 0 {
			out.WriteByte('\n')
		}
		lineSlots = lineSlots[:0]
		collectSlots := len(slots) < MaxSlotsPerTask
		scanLine(&out, collapsed, hm, maskIPs, collectSlots, &lineSlots)

		if lineIdx == 0 && len(lineSlots) == 0 && collapsed != "" {
			if cols := splitHeaderColumns(collapsed); len(cols) >= 2 {
				header = &tableHeaderInfo{cols: cols, hasLeadingW: line0LeadingWS}
			}
		}
		if len(lineSlots) > 0 && len(slots) < MaxSlotsPerTask {
			if usedLabels == nil {
				usedLabels = make(map[string]int, 32)
			}
			tokens = assignLineSlotLabels(collapsed, lineIdx, header, lineSlots, streamPrefix, usedLabels, tokens, &slots)
		}

		lineIdx++
		if hasNL && pos == len(collapsedText) {
			break
		}
	}

	return out.String(), slots, truncated
}

// collapsePreviewLines collapses runs of space/tab within each line to a single
// space, trims trailing space/tab and '\r' before '\n', and enforces MaxLineBytes
// per line (returning the original string zero-copy if already clean).
func collapsePreviewLines(text string) (string, bool) {
	needs := false
	prevSpace := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\t' || c == '\r' || (c == ' ' && prevSpace) || (c == '\n' && prevSpace) {
			needs = true
			break
		}
		prevSpace = c == ' '
	}
	if !needs && !prevSpace {
		return text, false
	}

	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	lineIdx := 0
	truncated := false
	for pos <= len(text) {
		if lineIdx >= MaxLinesPerPreview {
			truncated = true
			break
		}
		nl := strings.IndexByte(text[pos:], '\n')
		var rawLine string
		var hasNL bool
		if nl < 0 {
			rawLine = text[pos:]
			pos = len(text) + 1
		} else {
			rawLine = text[pos : pos+nl]
			pos += nl + 1
			hasNL = true
		}
		rawLine = strings.TrimSuffix(rawLine, "\r")
		if len(rawLine) > MaxLineBytes {
			rawLine = truncateUTF8Bytes(rawLine, MaxLineBytes)
			truncated = true
		}
		if lineIdx > 0 {
			b.WriteByte('\n')
		}
		writeCollapsedLine(&b, rawLine)
		lineIdx++
		if hasNL && pos == len(text) {
			b.WriteByte('\n')
			break
		}
	}
	return b.String(), truncated
}

func writeCollapsedLine(b *strings.Builder, s string) {
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	inWS := false
	for i := 0; i < end; i++ {
		if c := s[i]; c == ' ' || c == '\t' {
			if !inWS {
				b.WriteByte(' ')
				inWS = true
			}
		} else {
			b.WriteByte(c)
			inWS = false
		}
	}
}

// collapseWhitespace collapses runs of space/tab into a single space and trims
// trailing spaces/tabs.
func collapseWhitespace(s string) string {
	if s == "" {
		return ""
	}
	needsCopy := false
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || (c == ' ' && prevSpace) {
			needsCopy = true
			break
		}
		prevSpace = c == ' '
	}
	if !needsCopy {
		if prevSpace {
			return s[:len(s)-1]
		}
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	writeCollapsedLine(&b, s)
	return b.String()
}

func splitHeaderColumns(collapsed string) []string {
	trimmed := strings.TrimSpace(collapsed)
	if trimmed == "" {
		return nil
	}
	fields := strings.Fields(trimmed)
	for _, f := range fields {
		if strings.HasSuffix(f, ":") || strings.Contains(f, "=") {
			return nil
		}
	}
	return fields
}

func assignLineSlotLabels(
	collapsed string,
	lineIdx int,
	header *tableHeaderInfo,
	lineSlots []rawLineSlot,
	streamPrefix string,
	usedLabels map[string]int,
	tokens []byteSpan,
	slots *[]MetricSlot,
) []byteSpan {
	tokens = tokens[:0]
	if header != nil && lineIdx > 0 {
		for i := 0; i < len(collapsed); {
			for i < len(collapsed) && collapsed[i] == ' ' {
				i++
			}
			if i >= len(collapsed) {
				break
			}
			st := i
			for i < len(collapsed) && collapsed[i] != ' ' {
				i++
			}
			tokens = append(tokens, byteSpan{st, i})
		}
	}

	var rowKey string
	if header != nil && lineIdx > 0 && len(tokens) >= 2 {
		if !isSlotStartingAt(lineSlots, tokens[0].start) {
			rowKey = strings.TrimRight(collapsed[tokens[0].start:tokens[0].end], ":")
		}
	}

	for idx, rs := range lineSlots {
		if len(*slots) >= MaxSlotsPerTask {
			break
		}
		if !isFiniteFloat(rs.value) {
			continue
		}
		rawLabel := inferSlotLabel(collapsed, lineIdx, idx, rs, header, tokens, rowKey)
		if streamPrefix != "" {
			rawLabel = streamPrefix + rawLabel
		}
		*slots = append(*slots, MetricSlot{
			Label: dedupSanitizedLabel(rawLabel, usedLabels),
			Unit:  SanitizeLabel(rs.unit),
			Value: rs.value,
		})
	}
	return tokens
}

func inferSlotLabel(
	line string,
	lineIdx, slotIdx int,
	rs rawLineSlot,
	header *tableHeaderInfo,
	tokens []byteSpan,
	rowKey string,
) string {
	if key, commaIdx := findKVKeyBeforeParts(line, rs.start); key != "" {
		if commaIdx > 0 {
			return key + "[" + strconv.Itoa(commaIdx) + "]"
		}
		return key
	}

	if header != nil && rowKey != "" {
		for ti, tok := range tokens {
			if rs.start >= tok.start && rs.start < tok.end {
				if ti >= 1 {
					hIdx := ti
					if header.hasLeadingW {
						hIdx = ti - 1
					}
					if hIdx >= 0 && hIdx < len(header.cols) {
						return rowKey + "." + header.cols[hIdx]
					}
				}
				break
			}
		}
	}

	return "line" + strconv.Itoa(lineIdx) + ".slot" + strconv.Itoa(slotIdx)
}

func isSlotStartingAt(slots []rawLineSlot, pos int) bool {
	for _, s := range slots {
		if s.start == pos {
			return true
		}
	}
	return false
}

func findKVKeyBeforeParts(line string, start int) (string, int) {
	j := start
	for j > 0 && line[j-1] == ' ' {
		j--
	}
	commaIdx := 0
	for j > 0 && (line[j-1] == ',' || line[j-1] == ' ' || isDigit(line[j-1]) || line[j-1] == '.') {
		if line[j-1] == ',' {
			commaIdx++
		}
		j--
	}
	if j == 0 || (line[j-1] != ':' && line[j-1] != '=') {
		return "", 0
	}
	sep := line[j-1]
	j--
	for j > 0 && line[j-1] == ' ' {
		j--
	}
	if j == 0 || (commaIdx > 0 && sep != ':') {
		return "", 0
	}
	end := j
	spaces := 0
	for j > 0 {
		c := line[j-1]
		if isAlphaNum(c) || c == '_' || c == '-' || c == '.' || c == '/' {
			j--
		} else if c == ' ' && sep == ':' && spaces == 0 && j >= 2 && isAlpha(line[j-2]) {
			spaces++
			j--
		} else {
			break
		}
	}
	key := strings.TrimSpace(line[j:end])
	if key == "" || !containsAlpha(key) {
		return "", 0
	}
	return key, commaIdx
}

func containsAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if isAlpha(s[i]) {
			return true
		}
	}
	return false
}

func dedupSanitizedLabel(raw string, used map[string]int) string {
	base := SanitizeLabel(raw)
	if base == "" {
		base = "metric"
	}
	cnt := used[base]
	used[base] = cnt + 1
	if cnt == 0 {
		return base
	}
	suffix := "#" + strconv.Itoa(cnt+1)
	if len(base)+len(suffix) > MaxLabelBytes {
		base = strings.TrimRight(truncateUTF8Bytes(base, MaxLabelBytes-len(suffix)), " ")
	}
	return base + suffix
}

func writeIP(b *strings.Builder, raw string, hasPort, maskIPs bool) {
	if !maskIPs {
		b.WriteString(raw)
		return
	}
	if hasPort {
		b.WriteString("<IP_PORT>")
	} else {
		b.WriteString("<IP>")
	}
}

// scanLine runs the single-pass O(N) lexical scanner on a whitespace-collapsed line,
// writing normalized text into b and appending extracted numeric slots to *slots.
func scanLine(b *strings.Builder, line string, hm hostMatcher, maskIPs bool, collectSlots bool, slots *[]rawLineSlot) {
	n := len(line)
	for i := 0; i < n; {
		c := line[i]
		if c == ' ' {
			b.WriteByte(' ')
			i++
			continue
		}

		// Non-ASCII UTF-8 bytes: never split multi-byte runes.
		if c >= utf8.RuneSelf {
			if mLen := hm.match(line, i); mLen > 0 {
				b.WriteString("<HOST>")
				i += mLen
				continue
			}
			// Priority 10b: systemd CGroup tree PID ("├─12345" or "└─12345").
			if c == 0xe2 {
				if pLen, totalLen := matchCGroupPID(line, i); totalLen > 0 {
					b.WriteString(line[i : i+pLen])
					b.WriteString("<PID>")
					i += totalLen
					continue
				}
			}
			_, size := utf8.DecodeRuneInString(line[i:])
			b.WriteString(line[i : i+size])
			i += size
			continue
		}

		// Fast path for '[': [REDACTED:...], hostname, bracketed IPv6, or syslog [PID]:.
		if c == '[' {
			if strings.HasPrefix(line[i:], "[REDACTED:") {
				if closeIdx := strings.IndexByte(line[i:], ']'); closeIdx > 0 {
					b.WriteString(line[i : i+closeIdx+1])
					i += closeIdx + 1
					continue
				}
			}
			if mLen := hm.match(line, i); mLen > 0 {
				b.WriteString("<HOST>")
				i += mLen
				continue
			}
			if ipLen, hasPort := matchBracketIPv6(line, i); ipLen > 0 {
				writeIP(b, line[i:i+ipLen], hasPort, maskIPs)
				i += ipLen
				continue
			}
			if totalLen := matchBracketPID(line, i); totalLen > 0 {
				b.WriteString("[<PID>]:")
				i += totalLen
				continue
			}
			b.WriteByte('[')
			i++
			continue
		}

		// Mid-identifier bytes cannot start any lexical token other than '[' above.
		if i > 0 && isAlphaNum(line[i-1]) {
			if isAlphaNum(c) {
				start := i
				for i++; i < n && isAlphaNum(line[i]); i++ {
				}
				b.WriteString(line[start:i])
				continue
			}
			b.WriteByte(c)
			i++
			continue
		}

		// Priority 2: Task's own hostname & eligible short hostname -> <HOST>.
		if mLen := hm.match(line, i); mLen > 0 {
			b.WriteString("<HOST>")
			i += mLen
			continue
		}

		if isDigit(c) {
			if tsLen := matchDigitTimestamp(line, i); tsLen > 0 {
				b.WriteString("<TS>")
				i += tsLen
				continue
			}
			if timeLen := matchClockTime(line, i); timeLen > 0 {
				b.WriteString("<TIME>")
				i += timeLen
				continue
			}
			if uuidLen := matchUUID(line, i); uuidLen > 0 {
				b.WriteString("<UUID>")
				i += uuidLen
				continue
			}
			if ipLen, hasPort := matchBareIP(line, i); ipLen > 0 {
				writeIP(b, line[i:i+ipLen], hasPort, maskIPs)
				i += ipLen
				continue
			}
			if hexLen := matchHexToken(line, i); hexLen > 0 {
				b.WriteString("<HEX>")
				i += hexLen
				continue
			}
			if verLen := matchDigitVersion(line, i); verLen > 0 {
				b.WriteString(line[i : i+verLen])
				i += verLen
				continue
			}
			if numLen, ph, unit, val, ok := matchNumeric(line, i, collectSlots); ok {
				b.WriteString(ph)
				if collectSlots && isFiniteFloat(val) {
					*slots = append(*slots, rawLineSlot{start: i, end: i + numLen, unit: unit, value: val})
				}
				i += numLen
				continue
			}
			start := i
			for i++; i < n && isAlphaNum(line[i]); i++ {
			}
			b.WriteString(line[start:i])
			continue
		}

		if isAlpha(c) {
			if c >= 'A' && c <= 'Z' {
				if tsLen := matchAlphaTimestamp(line, i); tsLen > 0 {
					b.WriteString("<TS>")
					i += tsLen
					continue
				}
			}
			if isHexLetter(c) {
				if uuidLen := matchUUID(line, i); uuidLen > 0 {
					b.WriteString("<UUID>")
					i += uuidLen
					continue
				}
				if ipLen, hasPort := matchBareIPv6(line, i); ipLen > 0 {
					writeIP(b, line[i:i+ipLen], hasPort, maskIPs)
					i += ipLen
					continue
				}
				if hexLen := matchHexToken(line, i); hexLen > 0 {
					b.WriteString("<HEX>")
					i += hexLen
					continue
				}
			}
			lc := toLowerASCII(c)
			if lc == 'h' || lc == 'e' || lc == 's' || lc == 'c' {
				if semLen := matchSemanticCode(line, i); semLen > 0 {
					b.WriteString(line[i : i+semLen])
					i += semLen
					continue
				}
			}
			if verLen := matchAlphaVersion(line, i); verLen > 0 {
				b.WriteString(line[i : i+verLen])
				i += verLen
				continue
			}
			if lc == 'm' || lc == 'p' || lc == 't' {
				if pLen, totalLen := matchKeywordPID(line, i); totalLen > 0 {
					b.WriteString(line[i : i+pLen])
					b.WriteString("<PID>")
					i += totalLen
					continue
				}
			}
			start := i
			for i++; i < n && isAlphaNum(line[i]); i++ {
			}
			b.WriteString(line[start:i])
			continue
		}

		if c == '-' && i+1 < n && isDigit(line[i+1]) {
			if numLen, ph, unit, val, ok := matchNumeric(line, i, collectSlots); ok {
				b.WriteString(ph)
				if collectSlots && isFiniteFloat(val) {
					*slots = append(*slots, rawLineSlot{start: i, end: i + numLen, unit: unit, value: val})
				}
				i += numLen
				continue
			}
		}

		if c == ':' && i+1 < n && line[i+1] == ':' {
			if ipLen, hasPort := matchBareIPv6(line, i); ipLen > 0 {
				writeIP(b, line[i:i+ipLen], hasPort, maskIPs)
				i += ipLen
				continue
			}
		}

		b.WriteByte(c)
		i++
	}
}

const (
	ccDigit uint8 = 1 << iota
	ccAlpha
	ccHexLetter
)

var asciiClass = func() [256]uint8 {
	var t [256]uint8
	for c := '0'; c <= '9'; c++ {
		t[c] = ccDigit
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = ccAlpha
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = ccAlpha
	}
	for _, c := range "abcdefABCDEF" {
		t[c] |= ccHexLetter
	}
	return t
}()

func isDigit(b byte) bool     { return asciiClass[b]&ccDigit != 0 }
func isAlpha(b byte) bool     { return asciiClass[b]&ccAlpha != 0 }
func isAlphaNum(b byte) bool  { return asciiClass[b]&(ccDigit|ccAlpha) != 0 }
func isIdentChar(b byte) bool { return isAlphaNum(b) || b == '_' }
func isHexLetter(b byte) bool { return asciiClass[b]&ccHexLetter != 0 }
func isHexChar(b byte) bool   { return asciiClass[b]&(ccDigit|ccHexLetter) != 0 }

func toLowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if toLowerASCII(s[i]) != toLowerASCII(prefix[i]) {
			return false
		}
	}
	return true
}

func parseFixedDigits(s string, width, minVal, maxVal int) bool {
	if len(s) < width {
		return false
	}
	val := 0
	for i := 0; i < width; i++ {
		if !isDigit(s[i]) {
			return false
		}
		val = val*10 + int(s[i]-'0')
	}
	return val >= minVal && val <= maxVal
}

func matchBoundedUint(s string, maxDigits, minVal, maxVal int) int {
	j, val := 0, 0
	for j < len(s) && isDigit(s[j]) && j <= maxDigits {
		val = val*10 + int(s[j]-'0')
		j++
	}
	if j == 0 || j > maxDigits || val < minVal || val > maxVal || (j < len(s) && isAlphaNum(s[j])) {
		return 0
	}
	return j
}

func isWeekday3(s string) bool {
	if len(s) < 3 {
		return false
	}
	switch s[:3] {
	case "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun":
		return true
	}
	return false
}

func isMonth3(s string) bool {
	if len(s) < 3 {
		return false
	}
	switch s[:3] {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	}
	return false
}

func isTimezoneAbbr(s string) int {
	if len(s) >= 4 && (len(s) == 4 || !isAlphaNum(s[4])) {
		switch s[:4] {
		case "CEST", "AEDT", "AEST", "AKST", "AKDT", "ACST", "AWST":
			return 4
		}
	}
	if len(s) >= 3 && (len(s) == 3 || !isAlphaNum(s[3])) {
		switch s[:3] {
		case "UTC", "GMT", "CST", "EST", "PST", "EDT", "PDT", "CET", "JST", "IST", "BST", "MST", "MDT", "CDT", "KST", "SGT", "HKT":
			return 3
		}
	}
	return 0
}

func matchTimePart(s string) int {
	if len(s) < 8 || s[2] != ':' || s[5] != ':' ||
		!parseFixedDigits(s[0:], 2, 0, 23) ||
		!parseFixedDigits(s[3:], 2, 0, 59) ||
		!parseFixedDigits(s[6:], 2, 0, 60) {
		return 0
	}
	pos := 8
	if pos < len(s) && (s[pos] == '.' || s[pos] == ',') {
		j := pos + 1
		for j < len(s) && isDigit(s[j]) && j-pos <= 10 {
			j++
		}
		if j > pos+1 {
			pos = j
		}
	}
	return pos
}

func matchTZPart(s string) int {
	if len(s) == 0 {
		return 0
	}
	if s[0] == 'Z' && (len(s) == 1 || !isAlphaNum(s[1])) {
		return 1
	}
	if s[0] == '+' || s[0] == '-' {
		if len(s) >= 6 && s[3] == ':' && parseFixedDigits(s[1:], 2, 0, 23) && parseFixedDigits(s[4:], 2, 0, 59) && (len(s) == 6 || !isAlphaNum(s[6])) {
			return 6
		}
		if len(s) >= 5 && parseFixedDigits(s[1:], 2, 0, 23) && parseFixedDigits(s[3:], 2, 0, 59) && (len(s) == 5 || !isAlphaNum(s[5])) {
			return 5
		}
	}
	if s[0] == ' ' && len(s) > 1 {
		rest := s[1:]
		if rest[0] != ' ' {
			if tzOff := matchTZPart(rest); tzOff > 0 {
				total := 1 + tzOff
				if total < len(s) && s[total] == ' ' {
					if abbr := isTimezoneAbbr(s[total+1:]); abbr > 0 {
						total += 1 + abbr
					}
				}
				return total
			}
		}
		if abbr := isTimezoneAbbr(rest); abbr > 0 {
			return 1 + abbr
		}
	}
	return 0
}

func matchAlphaTimestamp(line string, i int) int {
	s := line[i:]
	n := len(s)
	if n < 14 || s[3] != ' ' {
		return 0
	}
	if n >= 15 && isWeekday3(s) {
		for _, sub := range [2]int{matchISODateTime(s[4:], true), matchSyslogDateTime(s[4:], true)} {
			if sub > 0 && (4+sub == n || !isAlphaNum(s[4+sub])) {
				return 4 + sub
			}
		}
	}
	if sub := matchSyslogDateTime(s, false); sub > 0 && (sub == n || !isAlphaNum(s[sub])) {
		return sub
	}
	return 0
}

func matchDigitTimestamp(line string, i int) int {
	s := line[i:]
	n := len(s)
	if n < 10 {
		return 0
	}
	if (s[4] == '-' || s[4] == '/') && s[7] == s[4] {
		if sub := matchISODateTime(s, false); sub > 0 && (sub == n || !isAlphaNum(s[sub])) {
			return sub
		}
	}
	if n >= 20 && s[2] == '/' && s[6] == '/' && s[11] == ':' &&
		parseFixedDigits(s[0:], 2, 1, 31) && isMonth3(s[3:]) && parseFixedDigits(s[7:], 4, 1900, 2199) {
		if tLen := matchTimePart(s[12:]); tLen > 0 {
			end := 12 + tLen
			end += matchTZPart(s[end:])
			if end == n || !isAlphaNum(s[end]) {
				return end
			}
		}
	}
	return 0
}

func matchISODateTime(s string, requireTime bool) int {
	if len(s) < 10 || (s[4] != '-' && s[4] != '/') || s[7] != s[4] ||
		!parseFixedDigits(s[0:], 4, 1900, 2199) ||
		!parseFixedDigits(s[5:], 2, 1, 12) ||
		!parseFixedDigits(s[8:], 2, 1, 31) {
		return 0
	}
	pos := 10
	if pos < len(s) && (s[pos] == 'T' || s[pos] == 't' || s[pos] == ' ') {
		if tLen := matchTimePart(s[pos+1:]); tLen > 0 {
			pos += 1 + tLen
			return pos + matchTZPart(s[pos:])
		}
	}
	if requireTime || (pos < len(s) && (s[pos] == '-' || s[pos] == '/' || isAlphaNum(s[pos]))) {
		return 0
	}
	return pos
}

func matchSyslogDateTime(s string, allowYear bool) int {
	if len(s) < 14 || s[3] != ' ' || !isMonth3(s) {
		return 0
	}
	pos := 4
	if !isDigit(s[pos]) {
		return 0
	}
	day := int(s[pos] - '0')
	pos++
	if pos < len(s) && isDigit(s[pos]) {
		day = day*10 + int(s[pos]-'0')
		pos++
	}
	if day < 1 || day > 31 || pos >= len(s) || s[pos] != ' ' {
		return 0
	}
	tLen := matchTimePart(s[pos+1:])
	if tLen == 0 {
		return 0
	}
	pos += 1 + tLen
	pos += matchTZPart(s[pos:])
	if allowYear && pos+5 <= len(s) && s[pos] == ' ' && parseFixedDigits(s[pos+1:], 4, 1900, 2199) {
		pos += 5
	}
	return pos
}

func matchClockTime(line string, i int) int {
	if i > 0 && line[i-1] == ':' {
		return 0
	}
	tLen := matchTimePart(line[i:])
	if tLen == 0 {
		return 0
	}
	end := i + tLen
	if end < len(line) && (isAlphaNum(line[end]) || line[end] == ':') {
		return 0
	}
	return tLen
}

func matchUUID(line string, i int) int {
	if i+36 > len(line) || line[i+8] != '-' || line[i+13] != '-' || line[i+18] != '-' || line[i+23] != '-' {
		return 0
	}
	for k := 0; k < 36; k++ {
		if k != 8 && k != 13 && k != 18 && k != 23 && !isHexChar(line[i+k]) {
			return 0
		}
	}
	if i+36 < len(line) && isAlphaNum(line[i+36]) {
		return 0
	}
	return 36
}

func matchBracketIPv6(line string, i int) (int, bool) {
	n := len(line)
	if i > 0 && isAlphaNum(line[i-1]) {
		return 0, false
	}
	closeIdx := strings.IndexByte(line[i+1:min(n, i+48)], ']')
	if closeIdx <= 0 {
		return 0, false
	}
	inner := line[i+1 : i+1+closeIdx]
	if !strings.ContainsRune(inner, ':') {
		return 0, false
	}
	addr, err := netip.ParseAddr(inner)
	if err != nil || !addr.Is6() {
		return 0, false
	}
	end := i + 1 + closeIdx + 1
	if end < n && line[end] == ':' {
		if pLen := matchBoundedUint(line[end+1:], 5, 1, 65535); pLen > 0 {
			return end + 1 + pLen - i, true
		}
	}
	if end == n || !isAlphaNum(line[end]) {
		return end - i, false
	}
	return 0, false
}

func matchBareIP(line string, i int) (int, bool) {
	if i > 0 && (line[i-1] == '.' || (line[i-1] == '/' && i >= 2 && isAlphaNum(line[i-2]))) {
		return 0, false
	}
	if v4Len, hasPort := matchIPv4(line, i); v4Len > 0 {
		return v4Len, hasPort
	}
	return matchBareIPv6(line, i)
}

func matchBareIPv6(line string, i int) (int, bool) {
	n := len(line)
	if i > 0 && (line[i-1] == '.' || (line[i-1] == '/' && i >= 2 && isAlphaNum(line[i-2]))) {
		return 0, false
	}
	if strings.HasPrefix(line[i:], ":::") {
		if pLen := matchBoundedUint(line[i+3:], 5, 1, 65535); pLen > 0 {
			return 3 + pLen, true
		}
	}
	maxEnd := min(n, i+46)
	j, colons := i, 0
	for ; j < maxEnd; j++ {
		c := line[j]
		if !isHexChar(c) && c != ':' && c != '.' {
			break
		}
		if c == ':' {
			colons++
		}
	}
	if colons < 2 {
		return 0, false
	}
	cand := line[i:j]
	if len(cand) > 2 && cand[len(cand)-1] == ':' && cand[len(cand)-2] != ':' {
		cand = cand[:len(cand)-1]
	}
	addr, err := netip.ParseAddr(cand)
	if err != nil || !addr.Is6() {
		return 0, false
	}
	end := i + len(cand)
	if end < n && line[end] == '/' {
		if cLen := matchBoundedUint(line[end+1:], 3, 0, 128); cLen > 0 {
			end += 1 + cLen
		}
	}
	if end < n && isAlphaNum(line[end]) {
		return 0, false
	}
	return end - i, false
}

func matchIPv4(line string, i int) (int, bool) {
	n := len(line)
	pos := i
	for octet := 0; octet < 4; octet++ {
		if octet > 0 {
			if pos >= n || line[pos] != '.' {
				return 0, false
			}
			pos++
		}
		start, val := pos, 0
		for pos < n && isDigit(line[pos]) && pos-start < 4 {
			val = val*10 + int(line[pos]-'0')
			pos++
		}
		dLen := pos - start
		if dLen == 0 || dLen > 3 || val > 255 || (dLen > 1 && line[start] == '0') {
			return 0, false
		}
	}
	if pos < n && (line[pos] == '.' || isAlphaNum(line[pos])) {
		return 0, false
	}
	if pos < n && line[pos] == ':' {
		if pLen := matchBoundedUint(line[pos+1:], 5, 1, 65535); pLen > 0 {
			return pos + 1 + pLen - i, true
		}
	}
	if pos < n && line[pos] == '/' {
		if cLen := matchBoundedUint(line[pos+1:], 3, 0, 32); cLen > 0 {
			return pos + 1 + cLen - i, false
		}
	}
	return pos - i, false
}

func matchHexToken(line string, i int) int {
	if i > 0 && line[i-1] == '_' {
		return 0
	}
	n := len(line)
	if i+2 < n && line[i] == '0' && (line[i+1] == 'x' || line[i+1] == 'X') && isHexChar(line[i+2]) {
		j := i + 2
		for j < n && isHexChar(line[j]) {
			j++
		}
		if j < n && isIdentChar(line[j]) {
			return 0
		}
		return j - i
	}
	j := i
	hasDigit, hasHex := false, false
	for ; j < n && isHexChar(line[j]); j++ {
		if isDigit(line[j]) {
			hasDigit = true
		} else {
			hasHex = true
		}
	}
	if j-i < 8 || !hasDigit || !hasHex || (j < n && isIdentChar(line[j])) {
		return 0
	}
	return j - i
}

var (
	semanticKeywords = []string{
		"http_status", "status_code", "exit_status", "exit_code", "exit code",
		"exitcode", "status", "signal", "errno", "code",
	}
	pidKeywords = []string{"main pid", "ppid", "tgid", "pid"}
)

func matchKeywordInt(s string, keywords []string, allowNeg bool, maxDigits int, rejectDotAlways bool) (int, int) {
	n := len(s)
	for _, kw := range keywords {
		if !hasPrefixFold(s, kw) || len(kw) >= n {
			continue
		}
		pos := len(kw)
		sep := s[pos]
		if sep != '=' && sep != ':' && sep != ' ' {
			continue
		}
		pos++
		if pos < n && s[pos] == ' ' && (sep == ':' || sep == '=') {
			pos++
		}
		if allowNeg && pos < n && s[pos] == '-' {
			pos++
		}
		dStart := pos
		for pos < n && isDigit(s[pos]) && pos-dStart < maxDigits {
			pos++
		}
		if pos == dStart {
			continue
		}
		if pos < n {
			c := s[pos]
			if isIdentChar(c) || c == '%' || (c == '.' && (rejectDotAlways || (pos+1 < n && isDigit(s[pos+1])))) {
				continue
			}
		}
		return dStart, pos
	}
	return 0, 0
}

func matchSemanticCode(line string, i int) int {
	if i > 0 && line[i-1] == '_' {
		return 0
	}
	s := line[i:]
	n := len(s)

	if hasPrefixFold(s, "HTTP") && n >= 8 {
		pos := 4
		if pos < n && s[pos] == '/' {
			pos++
			if dLen := scanDigits(s, pos); dLen == 0 {
				return 0
			} else {
				pos += dLen
			}
			if pos < n && s[pos] == '.' {
				pos++
				if dLen := scanDigits(s, pos); dLen == 0 {
					return 0
				} else {
					pos += dLen
				}
			}
		}
		if pos < n && s[pos] == ' ' && pos+4 <= n && parseFixedDigits(s[pos+1:], 3, 100, 599) {
			end := pos + 4
			if end == n || !isAlphaNum(s[end]) {
				return end
			}
		}
	}

	if hasPrefixFold(s, "exited") && n >= 9 {
		pos := 6
		if pos < n && s[pos] == ' ' {
			pos++
		}
		if pos < n && s[pos] == '(' {
			pos++
			dStart := pos
			for pos < n && isDigit(s[pos]) && pos-dStart < 5 {
				pos++
			}
			if pos > dStart && pos < n && s[pos] == ')' {
				return pos + 1
			}
		}
	}

	_, end := matchKeywordInt(s, semanticKeywords, true, 6, false)
	return end
}

func matchDigitVersion(line string, i int) int {
	if i > 0 && line[i-1] == '_' {
		return 0
	}
	s := line[i:]
	if vLen := matchDottedVersion(s, 3); vLen > 0 && (vLen == len(s) || !isIdentChar(s[vLen])) {
		return vLen
	}
	return 0
}

func matchAlphaVersion(line string, i int) int {
	if i > 0 && line[i-1] == '_' {
		return 0
	}
	s := line[i:]
	n := len(s)
	if (s[0] == 'v' || s[0] == 'V') && n >= 6 && isDigit(s[1]) {
		if vLen := matchDottedVersion(s[1:], 3); vLen > 0 && (1+vLen == n || !isIdentChar(s[1+vLen])) {
			return 1 + vLen
		}
	}
	pos := 1
	for pos < n && (isAlphaNum(s[pos]) || s[pos] == '_' || s[pos] == '-' || s[pos] == '.') {
		pos++
	}
	if pos+1 < n && s[pos] == '/' && isDigit(s[pos+1]) {
		if vLen := matchDottedVersion(s[pos+1:], 2); vLen > 0 && (pos+1+vLen == n || !isIdentChar(s[pos+1+vLen])) {
			return pos + 1 + vLen
		}
	}
	return 0
}

func matchDottedVersion(s string, minParts int) int {
	n := len(s)
	pos, parts := 0, 0
	for {
		dStart := pos
		for pos < n && isDigit(s[pos]) && pos-dStart < 6 {
			pos++
		}
		if pos == dStart {
			return 0
		}
		parts++
		if pos+1 < n && s[pos] == '.' && isDigit(s[pos+1]) {
			pos++
			continue
		}
		break
	}
	if parts < minParts {
		return 0
	}
	if pos+1 < n && (s[pos] == '-' || s[pos] == '+') && isAlphaNum(s[pos+1]) {
		for pos++; pos < n && (isAlphaNum(s[pos]) || s[pos] == '.' || s[pos] == '_' || s[pos] == '-' || s[pos] == '+' || s[pos] == '~'); pos++ {
		}
	}
	return pos
}

func matchBracketPID(line string, i int) int {
	s := line[i:]
	if len(s) < 4 || !isDigit(s[1]) {
		return 0
	}
	pos := 1
	for pos < len(s) && isDigit(s[pos]) && pos <= 8 {
		pos++
	}
	if pos > 1 && pos+1 < len(s) && s[pos] == ']' && s[pos+1] == ':' {
		return pos + 2
	}
	return 0
}

func matchCGroupPID(line string, i int) (int, int) {
	s := line[i:]
	if !strings.HasPrefix(s, "├─") && !strings.HasPrefix(s, "└─") {
		return 0, 0
	}
	pLen := len("├─")
	pos := pLen
	for pos < len(s) && isDigit(s[pos]) && pos-pLen < 8 {
		pos++
	}
	if pos > pLen && (pos == len(s) || s[pos] == ' ') {
		return pLen, pos
	}
	return 0, 0
}

func matchKeywordPID(line string, i int) (int, int) {
	if i > 0 && line[i-1] == '_' {
		return 0, 0
	}
	return matchKeywordInt(line[i:], pidKeywords, false, 8, true)
}

func scanDigits(s string, pos int) int {
	start := pos
	for pos < len(s) && isDigit(s[pos]) {
		pos++
	}
	return pos - start
}

func scanUnsignedDecimal(s string, i int) int {
	n := len(s)
	pos := i
	for pos < n && isDigit(s[pos]) {
		pos++
	}
	if pos == i {
		return i
	}
	if pos+1 < n && s[pos] == '.' && isDigit(s[pos+1]) {
		for pos += 2; pos < n && isDigit(s[pos]); pos++ {
		}
	}
	return pos
}

func parseFiniteOrNaN(s string, mult float64) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || !isFiniteFloat(v) {
		return math.NaN()
	}
	return v * mult
}

func isNegativeSignLeftContext(prev byte) bool {
	return prev == ' ' || prev == '=' || prev == ':' || prev == ',' || prev == '(' || prev == '[' || prev == '{'
}

// matchNumeric matches durations (<DUR>), percentages (<PCT>), byte sizes
// (<SIZE>), and standalone numbers (<NUM>) by scanning the numeric prefix once.
func matchNumeric(line string, i int, parseVal bool) (length int, placeholder, unit string, val float64, ok bool) {
	if i > 0 && (line[i-1] == '_' || line[i-1] == '.') {
		return 0, "", "", 0, false
	}
	n := len(line)
	negative := line[i] == '-'
	numStart := i
	if negative {
		if i > 0 && !isNegativeSignLeftContext(line[i-1]) {
			return 0, "", "", 0, false
		}
		numStart++
	}
	numEnd := scanUnsignedDecimal(line, numStart)
	if numEnd == numStart {
		return 0, "", "", 0, false
	}

	// Percentage: [-]?number%
	if numEnd < n && line[numEnd] == '%' {
		end := numEnd + 1
		if end == n || !isAlphaNum(line[end]) {
			if parseVal {
				val = parseFiniteOrNaN(line[i:numEnd], 1)
			}
			return end - i, "<PCT>", "%", val, true
		}
		return 0, "", "", 0, false
	}

	if !negative && numEnd < n {
		next := line[numEnd]
		if next == ' ' || isAlpha(next) || next >= utf8.RuneSelf {
			if durLen, ms, durOK := matchDuration(line, i, parseVal); durOK {
				return durLen, "<DUR>", "ms", ms, true
			}
			if sizeLen, bVal, sizeOK := matchSizeSuffix(line, i, numEnd, parseVal); sizeOK {
				return sizeLen, "<SIZE>", "bytes", bVal, true
			}
		}
	}

	// Standalone number: reject hyphenated identifier suffixes (e.g. web-010, utf-8).
	if !negative && i > 0 && line[i-1] == '-' && i >= 2 && isIdentChar(line[i-2]) {
		return 0, "", "", 0, false
	}
	end := numEnd
	if end < n && (line[end] == 'e' || line[end] == 'E') {
		ePos := end + 1
		if ePos < n && (line[ePos] == '+' || line[ePos] == '-') {
			ePos++
		}
		if dLen := scanDigits(line, ePos); dLen > 0 {
			end = ePos + dLen
		}
	}
	if end < n && isIdentChar(line[end]) {
		return 0, "", "", 0, false
	}
	if parseVal {
		val = parseFiniteOrNaN(line[i:end], 1)
	}
	return end - i, "<NUM>", "", val, true
}

func matchDuration(line string, i int, parseVal bool) (int, float64, bool) {
	pos := i
	totalMS := 0.0
	parts := 0
	for pos < len(line) {
		atomLen, ms, ok := matchDurationAtom(line, pos, parts > 0, parseVal)
		if !ok {
			break
		}
		if parseVal {
			totalMS += ms
		}
		pos += atomLen
		parts++
		if pos < len(line) && isDigit(line[pos]) {
			continue
		}
		if pos+1 < len(line) && line[pos] == ' ' && isDigit(line[pos+1]) {
			if nextLen, _, nextOK := matchDurationAtom(line, pos+1, true, false); nextOK && nextLen > 0 {
				pos++
				continue
			}
		}
		break
	}
	if parts == 0 {
		return 0, 0, false
	}
	return pos - i, totalMS, true
}

func matchDurationAtom(line string, i int, inCompound, parseVal bool) (int, float64, bool) {
	n := len(line)
	numEnd := scanUnsignedDecimal(line, i)
	if numEnd == i {
		return 0, 0, false
	}
	spaced := numEnd < n && line[numEnd] == ' '
	uStart := numEnd
	if spaced {
		uStart++
	}
	if uStart >= n {
		return 0, 0, false
	}
	if !spaced && (strings.HasPrefix(line[uStart:], "µs") || strings.HasPrefix(line[uStart:], "μs")) {
		uEnd := uStart + len("µs")
		if uEnd < n && isIdentChar(line[uEnd]) {
			return 0, 0, false
		}
		if !parseVal {
			return uEnd - i, 0, true
		}
		return uEnd - i, parseFiniteOrNaN(line[i:numEnd], 1e-3), true
	}
	uEnd := uStart
	for uEnd < n && isAlpha(line[uEnd]) {
		uEnd++
	}
	if uEnd == uStart || (uEnd < n && line[uEnd] == '_') {
		return 0, 0, false
	}
	mult, ok := durationUnitMS(line[uStart:uEnd], spaced, inCompound)
	if !ok {
		return 0, 0, false
	}
	if uEnd < n && isDigit(line[uEnd]) {
		if spaced {
			return 0, 0, false
		}
		if _, _, nextOK := matchDurationAtom(line, uEnd, true, false); !nextOK {
			return 0, 0, false
		}
	}
	if !parseVal {
		return uEnd - i, 0, true
	}
	return uEnd - i, parseFiniteOrNaN(line[i:numEnd], mult), true
}

const (
	msSec   = 1000.0
	msMin   = 60_000.0
	msHour  = 3_600_000.0
	msDay   = 86_400_000.0
	msWeek  = 7 * msDay
	msMonth = 30 * msDay
	msYear  = 365 * msDay
)

var (
	unspacedDurationUnits = map[string]float64{
		"ns": 1e-6, "us": 1e-3, "ms": 1,
		"s": msSec, "sec": msSec, "secs": msSec,
		"m": msMin, "min": msMin, "mins": msMin,
		"h": msHour, "hr": msHour, "hrs": msHour,
		"day": msDay, "days": msDay, "week": msWeek, "weeks": msWeek,
	}
	spacedDurationUnits = map[string]float64{
		"ns": 1e-6, "nanosecond": 1e-6, "nanoseconds": 1e-6,
		"us": 1e-3, "microsecond": 1e-3, "microseconds": 1e-3,
		"ms": 1, "millisecond": 1, "milliseconds": 1,
		"sec": msSec, "secs": msSec, "second": msSec, "seconds": msSec,
		"min": msMin, "mins": msMin, "minute": msMin, "minutes": msMin,
		"hr": msHour, "hrs": msHour, "hour": msHour, "hours": msHour,
		"day": msDay, "days": msDay, "week": msWeek, "weeks": msWeek,
		"month": msMonth, "months": msMonth, "year": msYear, "years": msYear,
	}
)

func durationUnitMS(unit string, spaced, inCompound bool) (float64, bool) {
	if !spaced {
		if unit == "d" {
			return msDay, inCompound
		}
		v, ok := unspacedDurationUnits[unit]
		return v, ok
	}
	v, ok := spacedDurationUnits[strings.ToLower(unit)]
	return v, ok
}

const (
	kiB = 1024.0
	miB = kiB * 1024.0
	giB = miB * 1024.0
	tiB = giB * 1024.0
	piB = tiB * 1024.0
	eiB = piB * 1024.0
)

var (
	unspacedSizeUnits = map[string]float64{
		"B": 1, "K": kiB, "M": miB, "G": giB, "T": tiB, "P": piB, "E": eiB,
	}
	commonSizeUnits = map[string]float64{
		"byte": 1, "bytes": 1,
		"kb": kiB, "ki": kiB, "kib": kiB,
		"mb": miB, "mi": miB, "mib": miB,
		"gb": giB, "gi": giB, "gib": giB,
		"tb": tiB, "ti": tiB, "tib": tiB,
		"pb": piB, "pi": piB, "pib": piB,
		"eb": eiB, "ei": eiB, "eib": eiB,
	}
)

func matchSizeSuffix(line string, i, numEnd int, parseVal bool) (int, float64, bool) {
	n := len(line)
	spaced := numEnd < n && line[numEnd] == ' '
	uStart := numEnd
	if spaced {
		uStart++
	}
	uEnd := uStart
	for uEnd < n && isAlpha(line[uEnd]) {
		uEnd++
	}
	if uEnd == uStart || (uEnd < n && isIdentChar(line[uEnd])) {
		return 0, 0, false
	}
	unit := line[uStart:uEnd]
	var mult float64
	var ok bool
	if !spaced {
		mult, ok = unspacedSizeUnits[unit]
	}
	if !ok {
		mult, ok = commonSizeUnits[strings.ToLower(unit)]
	}
	if !ok {
		return 0, 0, false
	}
	if !parseVal {
		return uEnd - i, 0, true
	}
	return uEnd - i, parseFiniteOrNaN(line[i:numEnd], mult), true
}
