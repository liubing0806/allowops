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
		truncated := s.TotalSize > uint64(len(s.Data)) || len(s.Data) > MaxPreviewBytesPerStream
		capped := capPreviewBytes(s.Data)
		trimmed := strings.TrimSpace(toValidUTF8(capped))
		if trimmed == "" {
			continue
		}
		hasNonEmpty = true

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

// NormalizePreview normalizes a single stream preview into a deterministic template
// and extracts bounded finite numeric slots.
func NormalizePreview(raw []byte, opts NormalizeOptions) NormalizeResult {
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
		// Fallback cleanly to text if forced JSON fails bounded validation.
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
	tmpl, slots, lineTrunc := normalizeTextPreview(prepared, hostMatcher, opts.MaskIPs, opts.StreamPrefix)
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

func isFiniteFloat(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}

func capPreviewBytes(raw []byte) []byte {
	if len(raw) <= MaxPreviewBytesPerStream {
		return raw
	}
	b := raw[:MaxPreviewBytesPerStream]
	// Trim any trailing incomplete UTF-8 sequence created by slicing.
	for len(b) > 0 && len(b) > MaxPreviewBytesPerStream-4 && !utf8.Valid(b) {
		// Only trim trailing continuation/start bytes that form an incomplete rune.
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
	full  string
	short string
}

func newHostMatcher(hostname string) hostMatcher {
	h := strings.TrimSpace(hostname)
	if h == "" {
		return hostMatcher{}
	}
	m := hostMatcher{full: h}
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
	if m.full == "" {
		return 0
	}
	if i > 0 && isAlphaNum(line[i-1]) {
		return 0
	}
	if len(m.full) <= len(line)-i && line[i:i+len(m.full)] == m.full {
		end := i + len(m.full)
		if end == len(line) || !isAlphaNum(line[end]) {
			return len(m.full)
		}
	}
	if m.short != "" && len(m.short) <= len(line)-i && line[i:i+len(m.short)] == m.short {
		end := i + len(m.short)
		if end == len(line) || !isAlphaNum(line[end]) {
			return len(m.short)
		}
	}
	return 0
}

type tableHeaderInfo struct {
	cols        []string
	hasLeadingW bool
}

func normalizeTextPreview(text string, hm hostMatcher, maskIPs bool, streamPrefix string) (string, []MetricSlot, bool) {
	if text == "" {
		return "", nil, false
	}

	var out strings.Builder
	out.Grow(len(text))

	var slots []MetricSlot
	usedLabels := make(map[string]int, 16)
	var header *tableHeaderInfo

	lineIdx := 0
	truncated := false
	pos := 0
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

		// Preserve knowledge of leading whitespace before collapsing for table header detection.
		leadingWS := len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t')
		collapsed := collapseWhitespace(rawLine)

		normLine, lineSlots := scanLine(collapsed, hm, maskIPs)
		if lineIdx == 0 && len(lineSlots) == 0 && collapsed != "" {
			if cols := splitHeaderColumns(collapsed); len(cols) >= 2 {
				header = &tableHeaderInfo{cols: cols, hasLeadingW: leadingWS}
			}
		}

		if len(lineSlots) > 0 && len(slots) < MaxSlotsPerTask {
			assignLineSlotLabels(collapsed, lineIdx, header, lineSlots, streamPrefix, usedLabels, &slots)
		}

		if lineIdx > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(normLine)
		lineIdx++

		if hasNL && pos == len(text) {
			// Trailing newline at end of input: preserve cleanly without emitting an extra phantom line
			// unless input was only "\n".
			break
		}
	}

	return out.String(), slots, truncated
}

// collapseWhitespace collapses runs of space/tab into a single space and trims
// trailing spaces/tabs.
func collapseWhitespace(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	inWS := false
	for i := 0; i < len(s); i++ {
		c := s[i]
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
	res := b.String()
	return strings.TrimRight(res, " ")
}

func splitHeaderColumns(collapsed string) []string {
	trimmed := strings.TrimSpace(collapsed)
	if trimmed == "" {
		return nil
	}
	fields := strings.Fields(trimmed)
	// Reject lines that look like prose sentences or key-value lines with colons.
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

type byteSpan struct {
	start int
	end   int
}

func assignLineSlotLabels(
	collapsed string,
	lineIdx int,
	header *tableHeaderInfo,
	lineSlots []rawLineSlot,
	streamPrefix string,
	usedLabels map[string]int,
	dst *[]MetricSlot,
) {
	// Precompute whitespace token spans for table column lookup.
	var tokens []byteSpan
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

	var rowKey string
	if header != nil && lineIdx > 0 && len(tokens) >= 2 {
		firstTok := collapsed[tokens[0].start:tokens[0].end]
		if !isSlotStartingAt(lineSlots, tokens[0].start) {
			rowKey = strings.TrimRight(firstTok, ":")
		}
	}

	for idx, rs := range lineSlots {
		if len(*dst) >= MaxSlotsPerTask {
			return
		}
		baseLabel := inferSlotLabel(collapsed, lineIdx, idx, rs, header, tokens, rowKey)
		if streamPrefix != "" {
			baseLabel = streamPrefix + baseLabel
		}
		label := dedupSanitizedLabel(baseLabel, usedLabels)
		unit := SanitizeLabel(rs.unit)
		if !isFiniteFloat(rs.value) {
			continue
		}
		*dst = append(*dst, MetricSlot{
			Label:     label,
			Unit:      unit,
			Value:     rs.value,
			IsInteger: rs.isInteger,
		})
	}
}

func isSlotStartingAt(slots []rawLineSlot, pos int) bool {
	for _, s := range slots {
		if s.start == pos {
			return true
		}
	}
	return false
}

func inferSlotLabel(
	line string,
	lineIdx int,
	slotIdx int,
	rs rawLineSlot,
	header *tableHeaderInfo,
	tokens []byteSpan,
	rowKey string,
) string {
	// 1. Check immediate KV prefix before rs.start (e.g. "Memory: 12.4M", "used=4123", "limit: 19062").
	if key := findKVKeyBefore(line, rs.start); key != "" {
		return key
	}

	// 2. Check table header mapping (e.g. df -h, free -m).
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
				return rowKey + "." + header.cols[hIdx]
			}
		}
	}

	// 3. Fallback positional label.
	return "line" + strconv.Itoa(lineIdx) + ".slot" + strconv.Itoa(slotIdx)
}

func findKVKeyBefore(line string, start int) string {
	j := start
	for j > 0 && line[j-1] == ' ' {
		j--
	}
	if j == 0 {
		return ""
	}
	// Handle comma-separated values after a key like "load average: 0.42, 0.38, 0.35".
	commaIdx := 0
	for j > 0 && (line[j-1] == ',' || line[j-1] == ' ' || isDigit(line[j-1]) || line[j-1] == '.') {
		if line[j-1] == ',' {
			commaIdx++
		}
		j--
	}
	if j == 0 || (line[j-1] != ':' && line[j-1] != '=') {
		return ""
	}
	sep := line[j-1]
	j--
	for j > 0 && line[j-1] == ' ' {
		j--
	}
	if j == 0 {
		return ""
	}
	// If commaIdx > 0, only allow multi-value keys with ':'.
	if commaIdx > 0 && sep != ':' {
		return ""
	}
	// Scan key backwards (allow letters, digits, '_', '-', '.', '/', and up to 1 space for two-word keys like "load average").
	end := j
	spaces := 0
	for j > 0 {
		c := line[j-1]
		if isAlphaNum(c) || c == '_' || c == '-' || c == '.' || c == '/' {
			j--
		} else if c == ' ' && sep == ':' && spaces < 1 {
			// Peek whether previous char is a letter.
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
		return ""
	}
	if commaIdx > 0 {
		return key + "[" + strconv.Itoa(commaIdx) + "]"
	}
	return key
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
	n := len(line)
	if n == 0 {
		return "", nil
	}

	var b strings.Builder
	b.Grow(n)
	var slots []rawLineSlot

	for i := 0; i < n; {
		// Priority 1: [REDACTED:...] preserved verbatim.
		if line[i] == '[' && strings.HasPrefix(line[i:], "[REDACTED:") {
			if closeIdx := strings.IndexByte(line[i:], ']'); closeIdx > 0 {
				b.WriteString(line[i : i+closeIdx+1])
				i += closeIdx + 1
				continue
			}
		}

		// Priority 2: Task's own hostname & eligible short hostname -> <HOST>.
		if mLen := hm.match(line, i); mLen > 0 {
			b.WriteString("<HOST>")
			i += mLen
			continue
		}

		// Priority 3: Timestamps (ISO8601/RFC3339, slash date, CLF date, syslog/systemd datetime) -> <TS>.
		if tsLen := matchTimestamp(line, i); tsLen > 0 {
			b.WriteString("<TS>")
			i += tsLen
			continue
		}

		// Priority 4: Pure clock time HH:MM:SS(.fff) -> <TIME>.
		if timeLen := matchClockTime(line, i); timeLen > 0 {
			b.WriteString("<TIME>")
			i += timeLen
			continue
		}

		// Priority 5: UUID (8-4-4-4-12 hex) -> <UUID>.
		if uuidLen := matchUUID(line, i); uuidLen > 0 {
			b.WriteString("<UUID>")
			i += uuidLen
			continue
		}

		// Priority 6: IPv4 / IPv6 (with optional :port / /cidr) -> <IP> / <IP_PORT> (or verbatim if !maskIPs).
		if ipLen, hasPort := matchIP(line, i); ipLen > 0 {
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

		// Priority 7: 0xHEX and length >= 8 hex strings containing at least one digit and one hex letter -> <HEX>.
		if hexLen := matchHexToken(line, i); hexLen > 0 {
			b.WriteString("<HEX>")
			i += hexLen
			continue
		}

		// Priority 9a (before Priority 8 for HTTP/1.1 500): Semantic status / exit code contexts -> preserve verbatim.
		if semLen := matchSemanticCode(line, i); semLen > 0 {
			b.WriteString(line[i : i+semLen])
			i += semLen
			continue
		}

		// Priority 8: Version numbers (SemVer / name/x.y[.z]) -> preserve verbatim.
		if verLen := matchVersion(line, i); verLen > 0 {
			b.WriteString(line[i : i+verLen])
			i += verLen
			continue
		}

		// Priority 10: Explicit PID contexts (pid=123, PID: 123, Main PID: 123, [123]:, ├─123) -> <PID>.
		if pidPrefixLen, pidTotalLen, pidSuffix := matchPID(line, i); pidTotalLen > 0 {
			b.WriteString(line[i : i+pidPrefixLen])
			b.WriteString("<PID>")
			b.WriteString(pidSuffix)
			i += pidTotalLen
			continue
		}

		// Priority 11: Durations (123ms, 4.5s, 12m34s, 3h20m, 2h 30min, 42 days, 5 hours, 3 min) -> <DUR>.
		if durLen, msVal, ok := matchDuration(line, i); ok {
			b.WriteString("<DUR>")
			if isFiniteFloat(msVal) {
				slots = append(slots, rawLineSlot{
					start: i,
					end:   i + durLen,
					unit:  "ms",
					value: msVal,
				})
			}
			i += durLen
			continue
		}

		// Priority 12: Percentages (42%, 99.2%) -> <PCT>.
		if pctLen, pctVal, ok := matchPercentage(line, i); ok {
			b.WriteString("<PCT>")
			if isFiniteFloat(pctVal) {
				slots = append(slots, rawLineSlot{
					start: i,
					end:   i + pctLen,
					unit:  "%",
					value: pctVal,
				})
			}
			i += pctLen
			continue
		}

		// Priority 13: Byte / capacity units (128K, 4.2G, 512MiB, 1024KB, 2.5T, 4096B) -> <SIZE>.
		if sizeLen, byteVal, ok := matchSize(line, i); ok {
			b.WriteString("<SIZE>")
			if isFiniteFloat(byteVal) {
				slots = append(slots, rawLineSlot{
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
		if numLen, numVal, isInt, finite, ok := matchStandaloneNumber(line, i); ok {
			b.WriteString("<NUM>")
			if finite {
				slots = append(slots, rawLineSlot{
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

		// Default: copy byte verbatim.
		b.WriteByte(line[i])
		i++
	}

	return b.String(), slots
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

func isHexChar(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
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
	// Common 3-4 letter uppercase TZ abbreviations (UTC, GMT, CST, EST, PST, EDT, PDT, CET, CEST, JST, IST, BST, MST, MDT).
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

// matchTimePart matches HH:MM:SS(.frac)? starting at s[0], returning bytes consumed.
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

// matchTZPart matches optional timezone suffix: Z, +HH:MM, +HHMM, " +HHMM", " UTC", " +0800 CST".
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
			// Handle " +0800 CST" as produced by docker ps CreatedAt.
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

// matchTimestamp matches Priority 3 timestamps at line[i].
func matchTimestamp(line string, i int) int {
	if i > 0 && isAlphaNum(line[i-1]) {
		return 0
	}
	s := line[i:]
	n := len(s)
	if n < 10 {
		return 0
	}

	// 3a. Optional weekday prefix for systemd / asctime: "Mon 2026-11-24 10:00:00 UTC" or "Mon Nov 24 12:34:56 UTC 2026"
	if n >= 15 && isWeekday3(s) && s[3] == ' ' {
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

	// 3b. ISO8601/RFC3339 or slash date: YYYY-MM-DD[...] or YYYY/MM/DD[...]
	if sub := matchISODateTime(s, false); sub > 0 {
		if sub == n || !isAlphaNum(s[sub]) {
			return sub
		}
	}

	// 3c. CLF date: DD/Mon/YYYY:HH:MM:SS( +HHMM)?
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

	// 3d. Syslog date: Mon DD HH:MM:SS (or Mon D HH:MM:SS)
	if sub := matchSyslogDateTime(s, false); sub > 0 {
		if sub == n || !isAlphaNum(s[sub]) {
			return sub
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
	// Standalone date YYYY-MM-DD or YYYY/MM/DD (must not be followed by another dash/slash+digit like a path/ID).
	if pos < len(s) && (s[pos] == '-' || s[pos] == '/' || isAlphaNum(s[pos])) {
		return 0
	}
	return pos
}

func matchSyslogDateTime(s string, allowYear bool) int {
	if len(s) < 14 || !isMonth3(s) || s[3] != ' ' {
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

// matchClockTime matches Priority 4: HH:MM:SS(.fff)?.
func matchClockTime(line string, i int) int {
	if i > 0 && (isAlphaNum(line[i-1]) || line[i-1] == ':') {
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

// matchUUID matches Priority 5: 8-4-4-4-12 hex.
func matchUUID(line string, i int) int {
	if i > 0 && isAlphaNum(line[i-1]) {
		return 0
	}
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

// matchIP matches Priority 6: IPv4 / IPv6 with optional :port or /cidr.
func matchIP(line string, i int) (int, bool) {
	n := len(line)
	// Bracketed IPv6: [addr] or [addr]:port
	if line[i] == '[' {
		if i > 0 && isAlphaNum(line[i-1]) {
			return 0, false
		}
		closeIdx := strings.IndexByte(line[i+1:min(n, i+48)], ']')
		if closeIdx > 0 {
			inner := line[i+1 : i+1+closeIdx]
			if strings.ContainsRune(inner, ':') {
				if addr, err := netip.ParseAddr(inner); err == nil && addr.Is6() {
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
				}
			}
		}
		return 0, false
	}

	// Left boundary for bare IPv4/IPv6.
	if i > 0 && (isAlphaNum(line[i-1]) || line[i-1] == '.') {
		return 0, false
	}
	// Do not match version-like "name/1.2.3.4" where single '/' follows an identifier char.
	if i > 0 && line[i-1] == '/' && (i >= 2 && isAlphaNum(line[i-2])) {
		return 0, false
	}

	// Special Docker/netstat IPv6 unspecified with port: ":::8080" -> "::" + ":8080"
	if strings.HasPrefix(line[i:], ":::") {
		if pLen := matchPort(line[i+3:]); pLen > 0 {
			end := i + 3 + pLen
			if end == n || !isAlphaNum(line[end]) {
				return end - i, true
			}
		}
	}

	// Fast candidate scan (max 45 bytes for IPv6).
	if !isHexChar(line[i]) && line[i] != ':' {
		return 0, false
	}

	// Try IPv4 first when starting with a digit.
	if isDigit(line[i]) {
		if v4Len, hasPort := matchIPv4(line, i); v4Len > 0 {
			return v4Len, hasPort
		}
	}

	// Try bare IPv6 (must contain at least two colons).
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
	// Trim trailing ':' if any (unless "::").
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
	// Optional :port
	if pos < n && line[pos] == ':' {
		if pLen := matchPort(line[pos+1:]); pLen > 0 {
			end := pos + 1 + pLen
			if end == n || !isAlphaNum(line[end]) {
				return end - i, true
			}
		}
	}
	// Optional /cidr
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

// matchHexToken matches Priority 7: 0x[0-9a-fA-F]+ or length >= 8 hex string with
// at least one digit and at least one hex letter (a-f/A-F).
func matchHexToken(line string, i int) int {
	if i > 0 && isIdentChar(line[i-1]) {
		return 0
	}
	n := len(line)
	// Form A: 0x... / 0X...
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
	// Form B: length >= 8 pure hex with at least one digit and at least one hex letter.
	if !isHexChar(line[i]) {
		return 0
	}
	j := i
	hasDigit := false
	hasHexLetter := false
	for j < n && isHexChar(line[j]) {
		if isDigit(line[j]) {
			hasDigit = true
		} else {
			hasHexLetter = true
		}
		j++
	}
	if j-i < 8 || !hasDigit || !hasHexLetter {
		return 0
	}
	if j < n && isIdentChar(line[j]) {
		return 0
	}
	return j - i
}

// matchSemanticCode matches Priority 9: HTTP status codes, status=/exit_code=/Exited (N)/signal N.
func matchSemanticCode(line string, i int) int {
	if i > 0 && isIdentChar(line[i-1]) {
		return 0
	}
	s := line[i:]
	n := len(s)

	// 9a. HTTP/1.x <code>, HTTP/2 <code>, HTTP/2.0 <code>, HTTP/3 <code>, HTTP <code>
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

	// 9b. Exited (137) / Exited(0)
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

	// 9c. Semantic keywords followed by =, :, or space and an integer code.
	keywords := [...]string{
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
	for _, kw := range keywords {
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
		// Must not be part of a decimal, duration, size, percentage, or identifier.
		if pos < n && (isAlphaNum(s[pos]) || s[pos] == '_' || s[pos] == '%' || (s[pos] == '.' && pos+1 < n && isDigit(s[pos+1]))) {
			continue
		}
		return pos
	}

	return 0
}

// matchVersion matches Priority 8:
//   - [vV]?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._~+-]+)?
//   - name/\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._~+-]+)?
func matchVersion(line string, i int) int {
	if i > 0 && isIdentChar(line[i-1]) {
		return 0
	}
	s := line[i:]
	n := len(s)

	// Form A: [vV]?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._~+-]+)?
	if s[0] == 'v' || s[0] == 'V' || isDigit(s[0]) {
		pos := 0
		if s[0] == 'v' || s[0] == 'V' {
			pos = 1
		}
		if vLen := matchDottedVersion(s[pos:], 3); vLen > 0 {
			end := pos + vLen
			if end == n || !isIdentChar(s[end]) {
				return end
			}
		}
	}

	// Form B: name/\d+\.\d+(?:\.\d+)?
	if isAlpha(s[0]) {
		pos := 1
		for pos < n && (isAlphaNum(s[pos]) || s[pos] == '_' || s[pos] == '-' || s[pos] == '.') {
			pos++
		}
		if pos < n && s[pos] == '/' {
			if vLen := matchDottedVersion(s[pos+1:], 2); vLen > 0 {
				end := pos + 1 + vLen
				if end == n || !isIdentChar(s[end]) {
					return end
				}
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
	// Optional prerelease/build suffix: -alpha.1+build.2
	if pos < n && (s[pos] == '-' || s[pos] == '+') && pos+1 < n && isAlphaNum(s[pos+1]) {
		pos++
		for pos < n && (isAlphaNum(s[pos]) || s[pos] == '.' || s[pos] == '_' || s[pos] == '-' || s[pos] == '+' || s[pos] == '~') {
			pos++
		}
	}
	return pos
}

// matchPID matches Priority 10: pid=123, PID: 123, Main PID: 123, [123]:, ├─123, └─123.
func matchPID(line string, i int) (prefixLen int, totalLen int, suffix string) {
	s := line[i:]
	n := len(s)

	// 10a. Syslog bracket PID: [12345]:
	if s[0] == '[' && n >= 4 {
		pos := 1
		for pos < n && isDigit(s[pos]) && pos <= 8 {
			pos++
		}
		if pos > 1 && pos+1 < n && s[pos] == ']' && s[pos+1] == ':' {
			return 1, pos + 2, "]:"
		}
	}

	// 10b. systemd CGroup tree PID: "├─12345 " or "└─12345 " (UTF-8 box drawing prefix, 6 bytes)
	if strings.HasPrefix(s, "├─") || strings.HasPrefix(s, "└─") {
		pLen := len("├─") // 6 bytes for both ├─ and └─
		pos := pLen
		for pos < n && isDigit(s[pos]) && pos-pLen < 8 {
			pos++
		}
		if pos > pLen && (pos == n || s[pos] == ' ') {
			return pLen, pos, ""
		}
	}

	// 10c. Explicit keyword PID: Main PID: 123, PID: 123, pid=123, ppid=123
	if i > 0 && isIdentChar(line[i-1]) {
		return 0, 0, ""
	}
	prefixes := [...]string{"main pid", "ppid", "tgid", "pid"}
	for _, kw := range prefixes {
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

// matchDuration matches Priority 11 durations (including compound forms like
// "12m34s", "3h20m", "2h 30min", "42 days", "5 hours", "3 min") and returns
// total finite milliseconds.
func matchDuration(line string, i int) (int, float64, bool) {
	if i > 0 && (isIdentChar(line[i-1]) || line[i-1] == '.') {
		return 0, 0, false
	}
	if !isDigit(line[i]) {
		return 0, 0, false
	}

	pos := i
	totalMS := 0.0
	parts := 0
	for pos < len(line) {
		atomLen, ms, ok := matchDurationAtom(line, pos, parts > 0)
		if !ok {
			break
		}
		totalMS += ms
		pos += atomLen
		parts++

		// Allow adjacent compact part (e.g. 12m34s, 3h20m) or single-space separated part (e.g. 2h 30min, 1 day 4h).
		if pos < len(line) && isDigit(line[pos]) {
			continue
		}
		if pos+1 < len(line) && line[pos] == ' ' && isDigit(line[pos+1]) {
			if nextLen, _, nextOK := matchDurationAtom(line, pos+1, true); nextOK && nextLen > 0 {
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

func matchDurationAtom(line string, i int, inCompound bool) (int, float64, bool) {
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

	// Optional single space before word duration units (e.g. "42 days", "3 min").
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
	// Handle UTF-8 micro sign µ (\xc2\xb5) or Greek mu μ (\xce\xbc) followed by 's'.
	if !spaced && (strings.HasPrefix(line[uStart:], "µs") || strings.HasPrefix(line[uStart:], "μs")) {
		uEnd = uStart + len("µs")
		if uEnd < n && isIdentChar(line[uEnd]) {
			return 0, 0, false
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
	if uEnd == uStart {
		return 0, 0, false
	}
	// If compact compound like "12m34s", line[uEnd] may be a digit (the next duration atom!).
	if uEnd < n && line[uEnd] == '_' {
		return 0, 0, false
	}
	unit := line[uStart:uEnd]
	mult, ok := durationUnitMS(unit, spaced, inCompound)
	if !ok {
		return 0, 0, false
	}
	// If followed by digit, only valid for compact units (not spaced words like "5 hours3").
	if uEnd < n && isDigit(line[uEnd]) {
		if spaced {
			return 0, 0, false
		}
		// Verify the rest starts another valid duration atom.
		if _, _, nextOK := matchDurationAtom(line, uEnd, true); !nextOK {
			return 0, 0, false
		}
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
	// Spaced word units (case-insensitive).
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

// matchPercentage matches Priority 12: 42%, 99.2%.
func matchPercentage(line string, i int) (int, float64, bool) {
	if i > 0 && (isIdentChar(line[i-1]) || line[i-1] == '.') {
		return 0, 0, false
	}
	pos := i
	n := len(line)
	if pos < n && line[pos] == '-' {
		if i > 0 && isIdentChar(line[i-1]) {
			return 0, 0, false
		}
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
	val, err := strconv.ParseFloat(line[i:pos], 64)
	if err != nil || !isFiniteFloat(val) {
		return end - i, math.NaN(), true
	}
	return end - i, val, true
}

// matchSize matches Priority 13: 128K, 4.2G, 512MiB, 1024KB, 2.5T, 4096B (1024-base bytes).
func matchSize(line string, i int) (int, float64, bool) {
	if i > 0 && (isIdentChar(line[i-1]) || line[i-1] == '.') {
		return 0, 0, false
	}
	if !isDigit(line[i]) {
		return 0, 0, false
	}
	n := len(line)
	pos := i
	for pos < n && isDigit(line[pos]) {
		pos++
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
		// Single-letter units must be uppercase to avoid colliding with "5m" (minutes) or "2g".
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

// matchStandaloneNumber matches Priority 14 standalone integers/floats (including scientific notation).
func matchStandaloneNumber(line string, i int) (length int, val float64, isInt bool, finite bool, ok bool) {
	n := len(line)
	if i > 0 {
		prev := line[i-1]
		if isIdentChar(prev) || prev == '.' {
			return 0, 0, false, false, false
		}
		// Prevent breaking hyphenated tokens like utf-8, sha-256, x86-64.
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
	} else if !isDigit(line[pos]) {
		return 0, 0, false, false, false
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
