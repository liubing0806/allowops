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
	Label     string  // sanitized valid UTF-8, <= MaxLabelBytes
	Unit      string  // sanitized valid UTF-8, <= MaxLabelBytes ("%", "bytes", "ms", or "")
	Value     float64 // strictly finite (!NaN && !Inf)
	IsInteger bool    // true if parsed from a bare integer without unit or decimal
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
			// Neither a JSON object nor NDJSON of JSON objects can start with anything other than '{'.
			return PreviewModeText
		}

		truncated := s.TotalSize > uint64(len(s.Data)) || len(s.Data) > MaxPreviewBytesPerStream
		trimmed := strings.TrimSpace(toValidUTF8(capped))
		if trimmed == "" {
			continue
		}

		if allSingleJSON {
			if truncated || trimmed[0] != '{' || !isBoundedJSONObject(trimmed) {
				allSingleJSON = false
			}
		}

		if allNDJSON {
			prepared := preparePreviewText(capped, truncated)
			if !isBoundedNDJSON(prepared) {
				allNDJSON = false
			}
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
	var sc normalizeScratch
	res := normalizePreviewWithScratch(raw, opts, &sc, true)
	// Detach slots slice when backed by scratch (already standalone on single call).
	return res
}

// normalizeScratch holds per-call reusable buffers for Cluster and Diff loops.
// It is never shared across goroutines.
type normalizeScratch struct {
	out         strings.Builder
	lineSlots   []rawLineSlot
	tokens      []byteSpan
	usedLabels  map[string]int
	labelIntern map[string]string
	slots       []MetricSlot
	labelBuf    [MaxLabelBytes + 16]byte
}

func (sc *normalizeScratch) internLabel(b []byte) string {
	if sc.labelIntern == nil {
		sc.labelIntern = make(map[string]string, 64)
	}
	if s, ok := sc.labelIntern[string(b)]; ok {
		return s
	}
	s := string(b)
	if len(sc.labelIntern) < 1024 {
		sc.labelIntern[s] = s
	}
	return s
}

func normalizePreviewWithScratch(raw []byte, opts NormalizeOptions, sc *normalizeScratch, copyResult bool) NormalizeResult {
	wasTruncated := opts.Truncated || len(raw) > MaxPreviewBytesPerStream
	capped := capPreviewBytes(raw)
	if len(capped) == 0 {
		h := sha256.Sum256(nil)
		return NormalizeResult{
			Template:  "",
			Hash:      h,
			Mode:      resolveModeOrText(opts.Mode),
			Truncated: wasTruncated,
		}
	}

	mode := opts.Mode
	if mode == PreviewModeAuto {
		first, ok := firstNonWhitespaceByte(capped)
		if !ok || first != '{' {
			mode = PreviewModeText
		} else {
			trimmed := strings.TrimSpace(toValidUTF8(capped))
			if trimmed == "" {
				mode = PreviewModeText
			} else if !wasTruncated && trimmed[0] == '{' && isBoundedJSONObject(trimmed) {
				mode = PreviewModeJSON
			} else if isBoundedNDJSON(preparePreviewText(capped, wasTruncated)) {
				mode = PreviewModeNDJSON
			} else {
				mode = PreviewModeText
			}
		}
	}

	hostMatcher := newHostMatcher(opts.Hostname)
	switch mode {
	case PreviewModeJSON:
		text := strings.TrimSpace(toValidUTF8(capped))
		if tmpl, slots, ok := normalizeSingleJSON(text, hostMatcher, opts.MaskIPs, opts.StreamPrefix); ok {
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
		if tmpl, slots, ok := normalizeNDJSON(prepared, hostMatcher, opts.MaskIPs, opts.StreamPrefix); ok {
			return NormalizeResult{
				Template:  tmpl,
				Hash:      sha256.Sum256([]byte(tmpl)),
				Mode:      PreviewModeNDJSON,
				Slots:     slots,
				Truncated: wasTruncated,
			}
		}
		mode = PreviewModeText
	}

	prepared := preparePreviewText(capped, wasTruncated)
	tmpl, slots, lineTrunc := normalizeTextPreviewWithScratch(prepared, hostMatcher, opts.MaskIPs, opts.StreamPrefix, sc)
	if copyResult && len(slots) > 0 {
		cp := make([]MetricSlot, len(slots))
		copy(cp, slots)
		slots = cp
	}
	return NormalizeResult{
		Template:  tmpl,
		Hash:      sha256.Sum256([]byte(tmpl)),
		Mode:      mode,
		Slots:     slots,
		Truncated: wasTruncated || lineTrunc,
	}
}

func resolveModeOrText(m PreviewMode) PreviewMode {
	if m == PreviewModeAuto {
		return PreviewModeText
	}
	return m
}

// SanitizeLabel strips control characters (< 0x20 and 0x7f), collapses
// consecutive whitespace to a single space, ensures valid UTF-8, and truncates
// to at most MaxLabelBytes on a valid rune boundary.
func SanitizeLabel(s string) string {
	if s == "" {
		return ""
	}
	// Fast path: already clean ASCII <= MaxLabelBytes with no control chars,
	// no leading/trailing spaces, and no repeated spaces.
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
	out := b.String()
	out = strings.TrimRight(out, " ")
	return out
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
		last := b[len(b)-1]
		if last < 0x80 {
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
	// Sanitize hostname to valid UTF-8 so matching can never split a multi-byte rune.
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
		if len(cand) >= 3 && hasDigitOrHyphen(cand) {
			m.short = cand
		}
	}
	return m
}

func hasDigitOrHyphen(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '-' || (s[i] >= '0' && s[i] <= '9') {
			return true
		}
	}
	return false
}

func (m hostMatcher) match(line string, i int) int {
	if m.full == "" || line[i] != m.firstByte {
		return 0
	}
	if i > 0 && isAlphaNum(line[i-1]) {
		return 0
	}
	if !utf8.RuneStart(line[i]) {
		return 0
	}
	if len(m.full) <= len(line)-i && line[i:i+len(m.full)] == m.full {
		end := i + len(m.full)
		if end == len(line) || (!isAlphaNum(line[end]) && utf8.RuneStart(line[end])) {
			return len(m.full)
		}
	}
	if m.short != "" && len(m.short) <= len(line)-i && line[i:i+len(m.short)] == m.short {
		end := i + len(m.short)
		if end == len(line) || (!isAlphaNum(line[end]) && utf8.RuneStart(line[end])) {
			return len(m.short)
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

func normalizeTextPreviewWithScratch(text string, hm hostMatcher, maskIPs bool, streamPrefix string, sc *normalizeScratch) (string, []MetricSlot, bool) {
	if text == "" {
		return "", nil, false
	}

	line0LeadingWS := text[0] == ' ' || text[0] == '\t'
	// Collapse per-line whitespace across the entire preview in a single pass
	// (1 allocation instead of 1 per line).
	collapsedText, truncated := collapsePreviewLines(text)

	sc.out.Reset()
	if sc.out.Cap() < len(collapsedText) {
		sc.out.Grow(len(collapsedText))
	}
	sc.slots = sc.slots[:0]
	if sc.usedLabels != nil {
		clear(sc.usedLabels)
	}
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
			sc.out.WriteByte('\n')
		}
		sc.lineSlots = sc.lineSlots[:0]
		collectSlots := len(sc.slots) < MaxSlotsPerTask
		scanLineInto(&sc.out, collapsed, hm, maskIPs, collectSlots, &sc.lineSlots)

		if lineIdx == 0 && len(sc.lineSlots) == 0 && collapsed != "" {
			if cols := splitHeaderColumns(collapsed); len(cols) >= 2 {
				header = &tableHeaderInfo{cols: cols, hasLeadingW: line0LeadingWS}
			}
		}

		if len(sc.lineSlots) > 0 && len(sc.slots) < MaxSlotsPerTask {
			if sc.usedLabels == nil {
				sc.usedLabels = make(map[string]int, 32)
			}
			assignLineSlotLabelsWithScratch(collapsed, lineIdx, header, sc.lineSlots, streamPrefix, sc)
		}

		lineIdx++
		if hasNL && pos == len(collapsedText) {
			break
		}
	}

	return sc.out.String(), sc.slots, truncated
}

// collapsePreviewLines collapses runs of space/tab within each line to a single
// space, trims trailing space/tab and '\r' before '\n', and enforces MaxLineBytes
// per line before collapsing (returning the original string if already clean).
func collapsePreviewLines(text string) (string, bool) {
	// Fast check: if no '\t', no '\r', no "  ", and no space before '\n' or EOF, zero-copy.
	needs := false
	prevSpace := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\t' || c == '\r' {
			needs = true
			break
		}
		if c == ' ' {
			if prevSpace {
				needs = true
				break
			}
			prevSpace = true
		} else if c == '\n' {
			if prevSpace {
				needs = true
				break
			}
			prevSpace = false
		} else {
			prevSpace = false
		}
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
		if len(rawLine) > 0 && rawLine[len(rawLine)-1] == '\r' {
			rawLine = rawLine[:len(rawLine)-1]
		}
		if len(rawLine) > MaxLineBytes {
			rawLine = truncateUTF8Bytes(rawLine, MaxLineBytes)
			truncated = true
		}
		if lineIdx > 0 {
			b.WriteByte('\n')
		}
		end := len(rawLine)
		for end > 0 && (rawLine[end-1] == ' ' || rawLine[end-1] == '\t') {
			end--
		}
		inWS := false
		for i := 0; i < end; i++ {
			c := rawLine[i]
			if c == ' ' || c == '\t' {
				if !inWS {
					b.WriteByte(' ')
					inWS = true
				}
			} else {
				b.WriteByte(c)
				inWS = false
			}
		}
		lineIdx++
		if hasNL && pos == len(text) {
			b.WriteByte('\n')
			break
		}
	}
	return b.String(), truncated
}

// collapseWhitespaceInto collapses runs of space/tab into a single space and
// trims trailing spaces/tabs, reusing scratch to avoid per-line allocations.
func collapseWhitespaceInto(s string, scratch *strings.Builder) string {
	if s == "" {
		return ""
	}
	// Fast path: check if line already has no tabs, no consecutive spaces, and no trailing space.
	needsCopy := false
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' {
			needsCopy = true
			break
		}
		if c == ' ' {
			if prevSpace {
				needsCopy = true
				break
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
	}
	if !needsCopy {
		if prevSpace {
			return s[:len(s)-1]
		}
		return s
	}

	scratch.Reset()
	scratch.Grow(len(s))
	inWS := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			if !inWS {
				scratch.WriteByte(' ')
				inWS = true
			}
		} else {
			scratch.WriteByte(c)
			inWS = false
		}
	}
	res := scratch.String()
	return strings.TrimRight(res, " ")
}

func collapseWhitespace(s string) string {
	var b strings.Builder
	return collapseWhitespaceInto(s, &b)
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

type rawLineSlot struct {
	start     int // byte offset in collapsed line
	end       int
	unit      string
	value     float64
	isInteger bool
}

func assignLineSlotLabelsWithScratch(
	collapsed string,
	lineIdx int,
	header *tableHeaderInfo,
	lineSlots []rawLineSlot,
	streamPrefix string,
	sc *normalizeScratch,
) {
	tokens := sc.tokens[:0]
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
	sc.tokens = tokens

	var rowKey string
	if header != nil && lineIdx > 0 && len(tokens) >= 2 {
		firstTok := collapsed[tokens[0].start:tokens[0].end]
		if !isSlotStartingAt(lineSlots, tokens[0].start) {
			rowKey = strings.TrimRight(firstTok, ":")
		}
	}

	for idx, rs := range lineSlots {
		if len(sc.slots) >= MaxSlotsPerTask {
			return
		}
		if !isFiniteFloat(rs.value) {
			continue
		}
		buf := sc.labelBuf[:0]
		if streamPrefix != "" {
			buf = append(buf, streamPrefix...)
		}
		buf = appendInferredSlotLabel(buf, collapsed, lineIdx, idx, rs, header, tokens, rowKey)
		label := dedupSanitizedLabelFromBytes(buf, sc)
		unit := SanitizeLabel(rs.unit)
		sc.slots = append(sc.slots, MetricSlot{
			Label:     label,
			Unit:      unit,
			Value:     rs.value,
			IsInteger: rs.isInteger,
		})
	}
}

func appendInferredSlotLabel(
	buf []byte,
	line string,
	lineIdx int,
	slotIdx int,
	rs rawLineSlot,
	header *tableHeaderInfo,
	tokens []byteSpan,
	rowKey string,
) []byte {
	if key, commaIdx := findKVKeyBeforeParts(line, rs.start); key != "" {
		buf = append(buf, key...)
		if commaIdx > 0 {
			buf = append(buf, '[')
			buf = strconv.AppendInt(buf, int64(commaIdx), 10)
			buf = append(buf, ']')
		}
		return buf
	}

	if header != nil && rowKey != "" {
		colIdx := -1
		for ti, tok := range tokens {
			if rs.start >= tok.start && rs.start < tok.end {
				colIdx = ti
				break
			}
		}
		if colIdx >= 1 {
			hIdx := colIdx
			if header.hasLeadingW {
				hIdx = colIdx - 1
			}
			if hIdx >= 0 && hIdx < len(header.cols) {
				buf = append(buf, rowKey...)
				buf = append(buf, '.')
				buf = append(buf, header.cols[hIdx]...)
				return buf
			}
		}
	}

	buf = append(buf, "line"...)
	buf = strconv.AppendInt(buf, int64(lineIdx), 10)
	buf = append(buf, ".slot"...)
	buf = strconv.AppendInt(buf, int64(slotIdx), 10)
	return buf
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
	if j == 0 {
		return "", 0
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
	if j == 0 {
		return "", 0
	}
	if commaIdx > 0 && sep != ':' {
		return "", 0
	}
	end := j
	spaces := 0
	for j > 0 {
		c := line[j-1]
		if isAlphaNum(c) || c == '_' || c == '-' || c == '.' || c == '/' {
			j--
		} else if c == ' ' && sep == ':' && spaces < 1 {
			if j >= 2 && isAlpha(line[j-2]) {
				spaces++
				j--
				continue
			}
			break
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

func dedupSanitizedLabelFromBytes(raw []byte, sc *normalizeScratch) string {
	var cleanBuf [MaxLabelBytes + 12]byte
	var clean []byte
	if len(raw) > 0 && len(raw) <= MaxLabelBytes && isCleanASCIILabelBytes(raw) {
		clean = append(cleanBuf[:0], raw...)
	} else {
		s := SanitizeLabel(string(raw))
		clean = append(cleanBuf[:0], s...)
	}
	if len(clean) == 0 {
		clean = append(cleanBuf[:0], "metric"...)
	}
	cnt := sc.usedLabels[string(clean)]
	if cnt == 0 {
		interned := sc.internLabel(clean)
		sc.usedLabels[interned] = 1
		return interned
	}
	// Increment existing entry using zero-alloc string conversion lookup.
	baseInterned := sc.internLabel(clean)
	sc.usedLabels[baseInterned] = cnt + 1

	var sufBuf [12]byte
	suf := append(sufBuf[:0], '#')
	suf = strconv.AppendInt(suf, int64(cnt+1), 10)
	if len(clean)+len(suf) > MaxLabelBytes {
		maxBase := MaxLabelBytes - len(suf)
		for maxBase > 0 && !utf8.RuneStart(clean[maxBase]) {
			maxBase--
		}
		clean = clean[:maxBase]
		for len(clean) > 0 && clean[len(clean)-1] == ' ' {
			clean = clean[:len(clean)-1]
		}
	}
	clean = append(clean, suf...)
	return sc.internLabel(clean)
}

func isCleanASCIILabelBytes(s []byte) bool {
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
		base = truncateUTF8Bytes(base, MaxLabelBytes-len(suffix))
		base = strings.TrimRight(base, " ")
	}
	return base + suffix
}

// scanLine runs the single-pass O(N) lexical scanner on a whitespace-collapsed line.
func scanLine(line string, hm hostMatcher, maskIPs bool) (string, []rawLineSlot) {
	if line == "" {
		return "", nil
	}
	var b strings.Builder
	b.Grow(len(line))
	var slots []rawLineSlot
	scanLineInto(&b, line, hm, maskIPs, true, &slots)
	return b.String(), slots
}

// scanLineInto writes the normalized version of collapsed line directly into b,
// appending extracted numeric slots to *slots when collectSlots is true.
func scanLineInto(b *strings.Builder, line string, hm hostMatcher, maskIPs bool, collectSlots bool, slots *[]rawLineSlot) {
	n := len(line)
	for i := 0; i < n; {
		c := line[i]

		// Fast path: space never starts a lexical token (unless hostname somehow starts with space, which TrimSpace prevents).
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
				if pidPrefixLen, pidTotalLen, pidSuffix := matchCGroupPID(line, i); pidTotalLen > 0 {
					b.WriteString(line[i : i+pidPrefixLen])
					b.WriteString("<PID>")
					b.WriteString(pidSuffix)
					i += pidTotalLen
					continue
				}
			}
			_, size := utf8.DecodeRuneInString(line[i:])
			b.WriteString(line[i : i+size])
			i += size
			continue
		}

		// Fast path for '[': only [REDACTED:...], bracketed IPv6, syslog [PID]:, or hostname.
		if c == '[' {
			// Priority 1: [REDACTED:...] preserved verbatim.
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
				if maskIPs {
					if hasPort {
						b.WriteString("<IP_PORT>")
					} else {
						b.WriteString("<IP>")
					}
				} else {
					b.WriteString(line[i : i+ipLen])
				}
				i += ipLen
				continue
			}
			if pidPrefixLen, pidTotalLen, pidSuffix := matchBracketPID(line, i); pidTotalLen > 0 {
				b.WriteString(line[i : i+pidPrefixLen])
				b.WriteString("<PID>")
				b.WriteString(pidSuffix)
				i += pidTotalLen
				continue
			}
			b.WriteByte('[')
			i++
			continue
		}

		// If previous byte is alphanumeric, NO token other than '[' (handled above) can start here;
		// copy the entire remaining alphanumeric run in one tight loop.
		if i > 0 && isAlphaNum(line[i-1]) {
			if isAlphaNum(c) {
				start := i
				i++
				for i < n && isAlphaNum(line[i]) {
					i++
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
			// Priority 3: ISO / slash / CLF timestamps starting with digit.
			if tsLen := matchDigitTimestamp(line, i); tsLen > 0 {
				b.WriteString("<TS>")
				i += tsLen
				continue
			}
			// Priority 4: Pure clock time HH:MM:SS(.fff).
			if timeLen := matchClockTime(line, i); timeLen > 0 {
				b.WriteString("<TIME>")
				i += timeLen
				continue
			}
			// Priority 5: UUID (8-4-4-4-12 hex).
			if uuidLen := matchUUID(line, i); uuidLen > 0 {
				b.WriteString("<UUID>")
				i += uuidLen
				continue
			}
			// Priority 6: IPv4 / bare IPv6 starting with digit.
			if ipLen, hasPort := matchBareIP(line, i); ipLen > 0 {
				if maskIPs {
					if hasPort {
						b.WriteString("<IP_PORT>")
					} else {
						b.WriteString("<IP>")
					}
				} else {
					b.WriteString(line[i : i+ipLen])
				}
				i += ipLen
				continue
			}
			// Priority 7: 0xHEX or >= 8 hex token.
			if hexLen := matchHexToken(line, i); hexLen > 0 {
				b.WriteString("<HEX>")
				i += hexLen
				continue
			}
			// Priority 8: Dotted SemVer starting with digit (e.g. 1.24.0).
			if verLen := matchDigitVersion(line, i); verLen > 0 {
				b.WriteString(line[i : i+verLen])
				i += verLen
				continue
			}
			// Priority 11: Durations -> <DUR>.
			if durLen, msVal, ok := matchDuration(line, i, collectSlots); ok {
				b.WriteString("<DUR>")
				if collectSlots && isFiniteFloat(msVal) {
					*slots = append(*slots, rawLineSlot{
						start: i,
						end:   i + durLen,
						unit:  "ms",
						value: msVal,
					})
				}
				i += durLen
				continue
			}
			// Priority 12: Percentages -> <PCT>.
			if pctLen, pctVal, ok := matchPercentage(line, i, collectSlots); ok {
				b.WriteString("<PCT>")
				if collectSlots && isFiniteFloat(pctVal) {
					*slots = append(*slots, rawLineSlot{
						start: i,
						end:   i + pctLen,
						unit:  "%",
						value: pctVal,
					})
				}
				i += pctLen
				continue
			}
			// Priority 13: Byte / capacity units -> <SIZE>.
			if sizeLen, byteVal, ok := matchSize(line, i, collectSlots); ok {
				b.WriteString("<SIZE>")
				if collectSlots && isFiniteFloat(byteVal) {
					*slots = append(*slots, rawLineSlot{
						start: i,
						end:   i + sizeLen,
						unit:  "bytes",
						value: byteVal,
					})
				}
				i += sizeLen
				continue
			}
			// Priority 14: Standalone integers / floats -> <NUM>.
			if numLen, numVal, isInt, finite, ok := matchStandaloneNumber(line, i, collectSlots); ok {
				b.WriteString("<NUM>")
				if collectSlots && finite {
					*slots = append(*slots, rawLineSlot{
						start:     i,
						end:       i + numLen,
						unit:      "",
						value:     numVal,
						isInteger: isInt,
					})
				}
				i += numLen
				continue
			}
			// Unmatched digit token (e.g. "0th" or "123abc"): copy alphanumeric run at once.
			start := i
			i++
			for i < n && isAlphaNum(line[i]) {
				i++
			}
			b.WriteString(line[start:i])
			continue
		}

		if isAlpha(c) {
			// Priority 3: Weekday / Month timestamps (only uppercase starting letters).
			if c >= 'A' && c <= 'Z' {
				if tsLen := matchAlphaTimestamp(line, i); tsLen > 0 {
					b.WriteString("<TS>")
					i += tsLen
					continue
				}
			}
			// Priority 5, 6, 7: UUID, bare IPv6, Hex (only when starting with hex letter a-f/A-F).
			if isHexLetter(c) {
				if uuidLen := matchUUID(line, i); uuidLen > 0 {
					b.WriteString("<UUID>")
					i += uuidLen
					continue
				}
				if ipLen, hasPort := matchBareIPv6(line, i); ipLen > 0 {
					if maskIPs {
						if hasPort {
							b.WriteString("<IP_PORT>")
						} else {
							b.WriteString("<IP>")
						}
					} else {
						b.WriteString(line[i : i+ipLen])
					}
					i += ipLen
					continue
				}
				if hexLen := matchHexToken(line, i); hexLen > 0 {
					b.WriteString("<HEX>")
					i += hexLen
					continue
				}
			}
			// Priority 9: Semantic status / exit code contexts (HTTP, Exited, status, exit_code, signal, errno, code).
			lc := toLowerASCII(c)
			if lc == 'h' || lc == 'e' || lc == 's' || lc == 'c' {
				if semLen := matchSemanticCode(line, i); semLen > 0 {
					b.WriteString(line[i : i+semLen])
					i += semLen
					continue
				}
			}
			// Priority 8: Version numbers (v1.2.3 or name/1.24.0).
			if verLen := matchAlphaVersion(line, i); verLen > 0 {
				b.WriteString(line[i : i+verLen])
				i += verLen
				continue
			}
			// Priority 10: Explicit keyword PID (Main PID, pid, ppid, tgid).
			if lc == 'm' || lc == 'p' || lc == 't' {
				if pidPrefixLen, pidTotalLen, pidSuffix := matchKeywordPID(line, i); pidTotalLen > 0 {
					b.WriteString(line[i : i+pidPrefixLen])
					b.WriteString("<PID>")
					b.WriteString(pidSuffix)
					i += pidTotalLen
					continue
				}
			}
			// Plain word/identifier: copy entire alphanumeric run at once!
			start := i
			i++
			for i < n && isAlphaNum(line[i]) {
				i++
			}
			b.WriteString(line[start:i])
			continue
		}

		if c == '-' && i+1 < n && isDigit(line[i+1]) {
			if pctLen, pctVal, ok := matchPercentage(line, i, collectSlots); ok {
				b.WriteString("<PCT>")
				if collectSlots && isFiniteFloat(pctVal) {
					*slots = append(*slots, rawLineSlot{
						start: i,
						end:   i + pctLen,
						unit:  "%",
						value: pctVal,
					})
				}
				i += pctLen
				continue
			}
			if numLen, numVal, isInt, finite, ok := matchStandaloneNumber(line, i, collectSlots); ok {
				b.WriteString("<NUM>")
				if collectSlots && finite {
					*slots = append(*slots, rawLineSlot{
						start:     i,
						end:       i + numLen,
						unit:      "",
						value:     numVal,
						isInteger: isInt,
					})
				}
				i += numLen
				continue
			}
		}

		if c == ':' && i+1 < n && line[i+1] == ':' {
			if ipLen, hasPort := matchBareIPv6(line, i); ipLen > 0 {
				if maskIPs {
					if hasPort {
						b.WriteString("<IP_PORT>")
					} else {
						b.WriteString("<IP>")
					}
				} else {
					b.WriteString(line[i : i+ipLen])
				}
				i += ipLen
				continue
			}
		}

		// Default: copy punctuation byte verbatim.
		b.WriteByte(c)
		i++
	}
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isAlphaNum(b byte) bool {
	return isAlpha(b) || isDigit(b)
}

func isIdentChar(b byte) bool {
	return isAlphaNum(b) || b == '_'
}

func isHexLetter(b byte) bool {
	return (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isHexChar(b byte) bool {
	return isDigit(b) || isHexLetter(b)
}

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

func parse2Digits(s string) (int, bool) {
	if len(s) < 2 || !isDigit(s[0]) || !isDigit(s[1]) {
		return 0, false
	}
	return int(s[0]-'0')*10 + int(s[1]-'0'), true
}

func parse4Digits(s string) (int, bool) {
	if len(s) < 4 || !isDigit(s[0]) || !isDigit(s[1]) || !isDigit(s[2]) || !isDigit(s[3]) {
		return 0, false
	}
	return int(s[0]-'0')*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0'), true
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
	if len(s) >= 4 {
		switch s[:4] {
		case "CEST", "AEDT", "AEST", "AKST", "AKDT", "ACST", "AWST":
			if len(s) == 4 || !isAlphaNum(s[4]) {
				return 4
			}
		}
	}
	if len(s) >= 3 {
		switch s[:3] {
		case "UTC", "GMT", "CST", "EST", "PST", "EDT", "PDT", "CET", "JST", "IST", "BST", "MST", "MDT", "CDT", "KST", "SGT", "HKT":
			if len(s) == 3 || !isAlphaNum(s[3]) {
				return 3
			}
		}
	}
	return 0
}

func matchTimePart(s string) int {
	if len(s) < 8 || s[2] != ':' || s[5] != ':' {
		return 0
	}
	hh, ok1 := parse2Digits(s[0:2])
	mm, ok2 := parse2Digits(s[3:5])
	ss, ok3 := parse2Digits(s[6:8])
	if !ok1 || !ok2 || !ok3 || hh > 23 || mm > 59 || ss > 60 {
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
		if len(s) >= 6 && s[3] == ':' {
			hh, ok1 := parse2Digits(s[1:3])
			mm, ok2 := parse2Digits(s[4:6])
			if ok1 && ok2 && hh <= 23 && mm <= 59 && (len(s) == 6 || !isAlphaNum(s[6])) {
				return 6
			}
		}
		if len(s) >= 5 {
			hh, ok1 := parse2Digits(s[1:3])
			mm, ok2 := parse2Digits(s[3:5])
			if ok1 && ok2 && hh <= 23 && mm <= 59 && (len(s) == 5 || !isAlphaNum(s[5])) {
				return 5
			}
		}
	}
	if s[0] == ' ' && len(s) > 1 {
		rest := s[1:]
		if tzOff := matchTZPart(rest); tzOff > 0 && rest[0] != ' ' {
			total := 1 + tzOff
			if total < len(s) && s[total] == ' ' {
				if abbr := isTimezoneAbbr(s[total+1:]); abbr > 0 {
					total += 1 + abbr
				}
			}
			return total
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
	if n < 14 {
		return 0
	}
	if n >= 15 && s[3] == ' ' && isWeekday3(s) {
		rest := s[4:]
		if sub := matchISODateTime(rest, true); sub > 0 {
			end := 4 + sub
			if end == n || !isAlphaNum(s[end]) {
				return end
			}
		}
		if sub := matchSyslogDateTime(rest, true); sub > 0 {
			end := 4 + sub
			if end == n || !isAlphaNum(s[end]) {
				return end
			}
		}
	}
	if s[3] == ' ' {
		if sub := matchSyslogDateTime(s, false); sub > 0 {
			if sub == n || !isAlphaNum(s[sub]) {
				return sub
			}
		}
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
		if sub := matchISODateTime(s, false); sub > 0 {
			if sub == n || !isAlphaNum(s[sub]) {
				return sub
			}
		}
	}
	if n >= 20 && s[2] == '/' && s[6] == '/' && s[11] == ':' {
		dd, ok1 := parse2Digits(s[0:2])
		yy, ok2 := parse4Digits(s[7:11])
		if ok1 && ok2 && dd >= 1 && dd <= 31 && yy >= 1900 && yy <= 2199 && isMonth3(s[3:6]) {
			if tLen := matchTimePart(s[12:]); tLen > 0 {
				end := 12 + tLen
				end += matchTZPart(s[end:])
				if end == n || !isAlphaNum(s[end]) {
					return end
				}
			}
		}
	}
	return 0
}

func matchISODateTime(s string, requireTime bool) int {
	if len(s) < 10 {
		return 0
	}
	sep := s[4]
	if (sep != '-' && sep != '/') || s[7] != sep {
		return 0
	}
	yy, ok1 := parse4Digits(s[0:4])
	mm, ok2 := parse2Digits(s[5:7])
	dd, ok3 := parse2Digits(s[8:10])
	if !ok1 || !ok2 || !ok3 || yy < 1900 || yy > 2199 || mm < 1 || mm > 12 || dd < 1 || dd > 31 {
		return 0
	}
	pos := 10
	if pos < len(s) && (s[pos] == 'T' || s[pos] == 't' || s[pos] == ' ') {
		if tLen := matchTimePart(s[pos+1:]); tLen > 0 {
			pos += 1 + tLen
			pos += matchTZPart(s[pos:])
			return pos
		}
	}
	if requireTime {
		return 0
	}
	if pos < len(s) && (s[pos] == '-' || s[pos] == '/' || isAlphaNum(s[pos])) {
		return 0
	}
	return pos
}

func matchSyslogDateTime(s string, allowYear bool) int {
	if len(s) < 14 || s[3] != ' ' || !isMonth3(s) {
		return 0
	}
	pos := 4
	if pos >= len(s) || !isDigit(s[pos]) {
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
	pos++
	tLen := matchTimePart(s[pos:])
	if tLen == 0 {
		return 0
	}
	pos += tLen
	pos += matchTZPart(s[pos:])
	if allowYear && pos+5 <= len(s) && s[pos] == ' ' {
		if yy, ok := parse4Digits(s[pos+1 : pos+5]); ok && yy >= 1900 && yy <= 2199 {
			pos += 5
		}
	}
	return pos
}

func matchClockTime(line string, i int) int {
	if i+8 > len(line) || line[i+2] != ':' || line[i+5] != ':' {
		return 0
	}
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
	if i+36 > len(line) {
		return 0
	}
	if line[i+8] != '-' || line[i+13] != '-' || line[i+18] != '-' || line[i+23] != '-' {
		return 0
	}
	for k := 0; k < 36; k++ {
		if k == 8 || k == 13 || k == 18 || k == 23 {
			continue
		}
		if !isHexChar(line[i+k]) {
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
		if pLen := matchPort(line[end+1:]); pLen > 0 {
			end += 1 + pLen
			if end == n || !isAlphaNum(line[end]) {
				return end - i, true
			}
		}
	}
	if end == n || !isAlphaNum(line[end]) {
		return end - i, false
	}
	return 0, false
}

func matchBareIP(line string, i int) (int, bool) {
	if i > 0 && line[i-1] == '.' {
		return 0, false
	}
	if i > 0 && line[i-1] == '/' && (i >= 2 && isAlphaNum(line[i-2])) {
		return 0, false
	}
	if v4Len, hasPort := matchIPv4(line, i); v4Len > 0 {
		return v4Len, hasPort
	}
	return matchBareIPv6(line, i)
}

func matchBareIPv6(line string, i int) (int, bool) {
	n := len(line)
	if i > 0 && line[i-1] == '.' {
		return 0, false
	}
	if i > 0 && line[i-1] == '/' && (i >= 2 && isAlphaNum(line[i-2])) {
		return 0, false
	}
	if strings.HasPrefix(line[i:], ":::") {
		if pLen := matchPort(line[i+3:]); pLen > 0 {
			end := i + 3 + pLen
			if end == n || !isAlphaNum(line[end]) {
				return end - i, true
			}
		}
	}
	maxEnd := min(n, i+46)
	j := i
	colons := 0
	for j < maxEnd {
		c := line[j]
		if isHexChar(c) || c == ':' || c == '.' {
			if c == ':' {
				colons++
			}
			j++
		} else {
			break
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
		if cLen := matchCIDR(line[end+1:], 128); cLen > 0 {
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
		start := pos
		val := 0
		for pos < n && isDigit(line[pos]) && pos-start < 4 {
			val = val*10 + int(line[pos]-'0')
			pos++
		}
		dLen := pos - start
		if dLen == 0 || dLen > 3 || val > 255 {
			return 0, false
		}
		if dLen > 1 && line[start] == '0' {
			return 0, false
		}
	}
	if pos < n && (line[pos] == '.' || isAlphaNum(line[pos])) {
		return 0, false
	}
	if pos < n && line[pos] == ':' {
		if pLen := matchPort(line[pos+1:]); pLen > 0 {
			end := pos + 1 + pLen
			if end == n || !isAlphaNum(line[end]) {
				return end - i, true
			}
		}
	}
	if pos < n && line[pos] == '/' {
		if cLen := matchCIDR(line[pos+1:], 32); cLen > 0 {
			end := pos + 1 + cLen
			if end == n || !isAlphaNum(line[end]) {
				return end - i, false
			}
		}
	}
	return pos - i, false
}

func matchPort(s string) int {
	j := 0
	val := 0
	for j < len(s) && isDigit(s[j]) && j < 6 {
		val = val*10 + int(s[j]-'0')
		j++
	}
	if j == 0 || j > 5 || val < 1 || val > 65535 {
		return 0
	}
	if j < len(s) && isAlphaNum(s[j]) {
		return 0
	}
	return j
}

func matchCIDR(s string, maxBits int) int {
	j := 0
	val := 0
	for j < len(s) && isDigit(s[j]) && j < 4 {
		val = val*10 + int(s[j]-'0')
		j++
	}
	if j == 0 || j > 3 || val > maxBits {
		return 0
	}
	if j < len(s) && isAlphaNum(s[j]) {
		return 0
	}
	return j
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
	hasDigit := false
	hasHex := false
	for j < n && isHexChar(line[j]) {
		if isDigit(line[j]) {
			hasDigit = true
		} else {
			hasHex = true
		}
		j++
	}
	if j-i < 8 || !hasDigit || !hasHex {
		return 0
	}
	if j < n && isIdentChar(line[j]) {
		return 0
	}
	return j - i
}

var semanticKeywords = [...]string{
	"http_status",
	"status_code",
	"exit_status",
	"exit_code",
	"exit code",
	"exitcode",
	"status",
	"signal",
	"errno",
	"code",
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
			dStart := pos
			for pos < n && isDigit(s[pos]) {
				pos++
			}
			if pos == dStart {
				return 0
			}
			if pos < n && s[pos] == '.' {
				pos++
				d2 := pos
				for pos < n && isDigit(s[pos]) {
					pos++
				}
				if pos == d2 {
					return 0
				}
			}
		}
		if pos < n && s[pos] == ' ' {
			pos++
			if pos+3 <= n && isDigit(s[pos]) && isDigit(s[pos+1]) && isDigit(s[pos+2]) {
				code := int(s[pos]-'0')*100 + int(s[pos+1]-'0')*10 + int(s[pos+2]-'0')
				end := pos + 3
				if code >= 100 && code <= 599 && (end == n || !isAlphaNum(s[end])) {
					return end
				}
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

	for _, kw := range semanticKeywords {
		if !hasPrefixFold(s, kw) {
			continue
		}
		pos := len(kw)
		if pos >= n {
			continue
		}
		sep := s[pos]
		if sep != '=' && sep != ':' && sep != ' ' {
			continue
		}
		pos++
		if pos < n && s[pos] == ' ' && (sep == ':' || sep == '=') {
			pos++
		}
		if pos < n && s[pos] == '-' {
			pos++
		}
		dStart := pos
		for pos < n && isDigit(s[pos]) && pos-dStart < 6 {
			pos++
		}
		if pos == dStart {
			continue
		}
		if pos < n && (isAlphaNum(s[pos]) || s[pos] == '_' || s[pos] == '%' || (s[pos] == '.' && pos+1 < n && isDigit(s[pos+1]))) {
			continue
		}
		return pos
	}

	return 0
}

func matchDigitVersion(line string, i int) int {
	if i > 0 && line[i-1] == '_' {
		return 0
	}
	s := line[i:]
	if vLen := matchDottedVersion(s, 3); vLen > 0 {
		if vLen == len(s) || !isIdentChar(s[vLen]) {
			return vLen
		}
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
		if vLen := matchDottedVersion(s[1:], 3); vLen > 0 {
			end := 1 + vLen
			if end == n || !isIdentChar(s[end]) {
				return end
			}
		}
	}
	pos := 1
	for pos < n && (isAlphaNum(s[pos]) || s[pos] == '_' || s[pos] == '-' || s[pos] == '.') {
		pos++
	}
	if pos < n && s[pos] == '/' && pos+1 < n && isDigit(s[pos+1]) {
		if vLen := matchDottedVersion(s[pos+1:], 2); vLen > 0 {
			end := pos + 1 + vLen
			if end == n || !isIdentChar(s[end]) {
				return end
			}
		}
	}
	return 0
}

func matchDottedVersion(s string, minParts int) int {
	n := len(s)
	pos := 0
	parts := 0
	for {
		dStart := pos
		for pos < n && isDigit(s[pos]) && pos-dStart < 6 {
			pos++
		}
		if pos == dStart {
			return 0
		}
		parts++
		if pos < n && s[pos] == '.' && pos+1 < n && isDigit(s[pos+1]) {
			pos++
			continue
		}
		break
	}
	if parts < minParts {
		return 0
	}
	if pos < n && (s[pos] == '-' || s[pos] == '+') && pos+1 < n && isAlphaNum(s[pos+1]) {
		pos++
		for pos < n && (isAlphaNum(s[pos]) || s[pos] == '.' || s[pos] == '_' || s[pos] == '-' || s[pos] == '+' || s[pos] == '~') {
			pos++
		}
	}
	return pos
}

func matchBracketPID(line string, i int) (int, int, string) {
	s := line[i:]
	n := len(s)
	if n < 4 || !isDigit(s[1]) {
		return 0, 0, ""
	}
	pos := 1
	for pos < n && isDigit(s[pos]) && pos <= 8 {
		pos++
	}
	if pos > 1 && pos+1 < n && s[pos] == ']' && s[pos+1] == ':' {
		return 1, pos + 2, "]:"
	}
	return 0, 0, ""
}

func matchCGroupPID(line string, i int) (int, int, string) {
	s := line[i:]
	n := len(s)
	if strings.HasPrefix(s, "├─") || strings.HasPrefix(s, "└─") {
		pLen := len("├─")
		pos := pLen
		for pos < n && isDigit(s[pos]) && pos-pLen < 8 {
			pos++
		}
		if pos > pLen && (pos == n || s[pos] == ' ') {
			return pLen, pos, ""
		}
	}
	return 0, 0, ""
}

var pidKeywords = [...]string{"main pid", "ppid", "tgid", "pid"}

func matchKeywordPID(line string, i int) (int, int, string) {
	if i > 0 && line[i-1] == '_' {
		return 0, 0, ""
	}
	s := line[i:]
	n := len(s)
	for _, kw := range pidKeywords {
		if !hasPrefixFold(s, kw) {
			continue
		}
		pos := len(kw)
		if pos >= n {
			continue
		}
		sep := s[pos]
		if sep != '=' && sep != ':' && sep != ' ' {
			continue
		}
		pos++
		if pos < n && s[pos] == ' ' && (sep == ':' || sep == '=') {
			pos++
		}
		dStart := pos
		for pos < n && isDigit(s[pos]) && pos-dStart < 8 {
			pos++
		}
		if pos == dStart {
			continue
		}
		if pos < n && (isIdentChar(s[pos]) || s[pos] == '.' || s[pos] == '%') {
			continue
		}
		return dStart, pos, ""
	}
	return 0, 0, ""
}

func matchDuration(line string, i int, parseVal bool) (int, float64, bool) {
	if i > 0 && (line[i-1] == '_' || line[i-1] == '.') {
		return 0, 0, false
	}

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

func matchDurationAtom(line string, i int, inCompound bool, parseVal bool) (int, float64, bool) {
	n := len(line)
	pos := i
	for pos < n && isDigit(line[pos]) {
		pos++
	}
	if pos == i {
		return 0, 0, false
	}
	if pos < n && line[pos] == '.' && pos+1 < n && isDigit(line[pos+1]) {
		pos++
		for pos < n && isDigit(line[pos]) {
			pos++
		}
	}
	numStr := line[i:pos]

	spaced := false
	uStart := pos
	if uStart < n && line[uStart] == ' ' {
		spaced = true
		uStart++
	}
	if uStart >= n {
		return 0, 0, false
	}

	uEnd := uStart
	if !spaced && (strings.HasPrefix(line[uStart:], "µs") || strings.HasPrefix(line[uStart:], "μs")) {
		uEnd = uStart + len("µs")
		if uEnd < n && isIdentChar(line[uEnd]) {
			return 0, 0, false
		}
		if !parseVal {
			return uEnd - i, 0, true
		}
		val, err := strconv.ParseFloat(numStr, 64)
		if err != nil || !isFiniteFloat(val) {
			return uEnd - i, math.NaN(), true
		}
		return uEnd - i, val * 1e-3, true
	}

	for uEnd < n && isAlpha(line[uEnd]) {
		uEnd++
	}
	if uEnd == uStart || (uEnd < n && line[uEnd] == '_') {
		return 0, 0, false
	}
	unit := line[uStart:uEnd]
	mult, ok := durationUnitMS(unit, spaced, inCompound)
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
	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil || !isFiniteFloat(val) {
		return uEnd - i, math.NaN(), true
	}
	return uEnd - i, val * mult, true
}

func durationUnitMS(unit string, spaced bool, inCompound bool) (float64, bool) {
	if !spaced {
		switch unit {
		case "ns":
			return 1e-6, true
		case "us":
			return 1e-3, true
		case "ms":
			return 1, true
		case "s", "sec", "secs":
			return 1000, true
		case "m", "min", "mins":
			return 60_000, true
		case "h", "hr", "hrs":
			return 3_600_000, true
		case "d":
			if inCompound {
				return 86_400_000, true
			}
			return 0, false
		case "day", "days":
			return 86_400_000, true
		case "week", "weeks":
			return 7 * 86_400_000, true
		}
		return 0, false
	}
	switch strings.ToLower(unit) {
	case "ns", "nanosecond", "nanoseconds":
		return 1e-6, true
	case "us", "microsecond", "microseconds":
		return 1e-3, true
	case "ms", "millisecond", "milliseconds":
		return 1, true
	case "sec", "secs", "second", "seconds":
		return 1000, true
	case "min", "mins", "minute", "minutes":
		return 60_000, true
	case "hr", "hrs", "hour", "hours":
		return 3_600_000, true
	case "day", "days":
		return 86_400_000, true
	case "week", "weeks":
		return 7 * 86_400_000, true
	case "month", "months":
		return 30 * 86_400_000, true
	case "year", "years":
		return 365 * 86_400_000, true
	}
	return 0, false
}

func matchPercentage(line string, i int, parseVal bool) (int, float64, bool) {
	if i > 0 && (line[i-1] == '_' || line[i-1] == '.') {
		return 0, 0, false
	}
	pos := i
	n := len(line)
	if pos < n && line[pos] == '-' {
		if i == 0 || isNegativeSignLeftContext(line[i-1]) {
			pos++
		} else {
			return 0, 0, false
		}
	}
	dStart := pos
	for pos < n && isDigit(line[pos]) {
		pos++
	}
	if pos == dStart {
		return 0, 0, false
	}
	if pos < n && line[pos] == '.' && pos+1 < n && isDigit(line[pos+1]) {
		pos++
		for pos < n && isDigit(line[pos]) {
			pos++
		}
	}
	if pos >= n || line[pos] != '%' {
		return 0, 0, false
	}
	end := pos + 1
	if end < n && isAlphaNum(line[end]) {
		return 0, 0, false
	}
	if !parseVal {
		return end - i, 0, true
	}
	val, err := strconv.ParseFloat(line[i:pos], 64)
	if err != nil || !isFiniteFloat(val) {
		return end - i, math.NaN(), true
	}
	return end - i, val, true
}

func matchSize(line string, i int, parseVal bool) (int, float64, bool) {
	if i > 0 && (line[i-1] == '_' || line[i-1] == '.') {
		return 0, 0, false
	}
	n := len(line)
	pos := i
	for pos < n && isDigit(line[pos]) {
		pos++
	}
	if pos == i {
		return 0, 0, false
	}
	if pos < n && line[pos] == '.' && pos+1 < n && isDigit(line[pos+1]) {
		pos++
		for pos < n && isDigit(line[pos]) {
			pos++
		}
	}
	numStr := line[i:pos]

	spaced := false
	uStart := pos
	if uStart < n && line[uStart] == ' ' {
		spaced = true
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
	mult, ok := sizeUnitBytes(unit, spaced)
	if !ok {
		return 0, 0, false
	}
	if !parseVal {
		return uEnd - i, 0, true
	}
	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil || !isFiniteFloat(val) {
		return uEnd - i, math.NaN(), true
	}
	return uEnd - i, val * mult, true
}

func sizeUnitBytes(unit string, spaced bool) (float64, bool) {
	const (
		kiB = 1024.0
		miB = kiB * 1024.0
		giB = miB * 1024.0
		tiB = giB * 1024.0
		piB = tiB * 1024.0
		eiB = piB * 1024.0
	)
	if !spaced {
		switch unit {
		case "B":
			return 1, true
		case "K":
			return kiB, true
		case "M":
			return miB, true
		case "G":
			return giB, true
		case "T":
			return tiB, true
		case "P":
			return piB, true
		case "E":
			return eiB, true
		}
	}
	switch strings.ToLower(unit) {
	case "byte", "bytes":
		return 1, true
	case "kb", "ki", "kib":
		return kiB, true
	case "mb", "mi", "mib":
		return miB, true
	case "gb", "gi", "gib":
		return giB, true
	case "tb", "ti", "tib":
		return tiB, true
	case "pb", "pi", "pib":
		return piB, true
	case "eb", "ei", "eib":
		return eiB, true
	}
	return 0, false
}

func isNegativeSignLeftContext(prev byte) bool {
	return prev == ' ' || prev == '=' || prev == ':' || prev == ',' || prev == '(' || prev == '[' || prev == '{'
}

func matchStandaloneNumber(line string, i int, parseVal bool) (length int, val float64, isInt bool, finite bool, ok bool) {
	n := len(line)
	if i > 0 {
		prev := line[i-1]
		if prev == '_' || prev == '.' {
			return 0, 0, false, false, false
		}
		if prev == '-' && i >= 2 && isIdentChar(line[i-2]) {
			return 0, 0, false, false, false
		}
	}

	pos := i
	if line[pos] == '-' {
		if i > 0 && !isNegativeSignLeftContext(line[i-1]) {
			return 0, 0, false, false, false
		}
		pos++
		if pos >= n || !isDigit(line[pos]) {
			return 0, 0, false, false, false
		}
	}

	for pos < n && isDigit(line[pos]) {
		pos++
	}
	hasDotOrExp := false
	if pos < n && line[pos] == '.' && pos+1 < n && isDigit(line[pos+1]) {
		hasDotOrExp = true
		pos++
		for pos < n && isDigit(line[pos]) {
			pos++
		}
	}
	if pos < n && (line[pos] == 'e' || line[pos] == 'E') {
		ePos := pos + 1
		if ePos < n && (line[ePos] == '+' || line[ePos] == '-') {
			ePos++
		}
		dStart := ePos
		for ePos < n && isDigit(line[ePos]) {
			ePos++
		}
		if ePos > dStart {
			hasDotOrExp = true
			pos = ePos
		}
	}

	if pos < n && isIdentChar(line[pos]) {
		return 0, 0, false, false, false
	}

	if !parseVal {
		return pos - i, 0, false, false, true
	}

	raw := line[i:pos]
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil || !isFiniteFloat(parsed) {
		return pos - i, 0, false, false, true
	}
	intOK := false
	if !hasDotOrExp {
		if _, iErr := strconv.ParseInt(raw, 10, 64); iErr == nil {
			intOK = true
		}
	}
	return pos - i, parsed, intOK, true, true
}
