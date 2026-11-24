// Package gitdocs provides the knowledge.git_markdown plugin for reading
// Markdown runbooks from a local directory or a remote .tar.gz archive.
package gitdocs

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/knowledge"
	"gopkg.in/yaml.v3"
)

const (
	moduleID = "knowledge.git_markdown"

	defaultRefreshTTL           = time.Minute
	maxRefreshTTL               = time.Hour
	defaultMaxFileBytes         = 512 << 10
	maxFileBytesLimit           = 1 << 20
	defaultMaxTotalBytes        = 16 << 20
	maxTotalBytesLimit          = 32 << 20
	defaultMaxFiles             = 1000
	maxFilesLimit               = 1000
	defaultMaxEntries           = 5000
	maxEntriesLimit             = 20000
	defaultStripComponents      = 1
	maxStripComponents          = 4
	defaultMaxArchiveBytes      = 8 << 20
	maxArchiveBytesLimit        = 32 << 20
	defaultMaxDecompressedBytes = 32 << 20
	maxDecompressedBytesLimit   = 64 << 20
	maxWalkDepth                = 16

	maxTitleBytes   = 256
	maxSummaryBytes = 512
	maxTags         = 32
	maxTagBytes     = 64
	maxHeadings     = 50
	maxHeadingBytes = 128
)

var (
	errSymlink               = errors.New("gitdocs: symlink rejected")
	errNonRegularFile        = errors.New("gitdocs: non-regular file rejected")
	errDepthLimit            = errors.New("gitdocs: directory depth exceeds limit")
	errEntryLimit            = errors.New("gitdocs: directory entries exceed limit")
	errFileLimit             = errors.New("gitdocs: markdown files exceed limit")
	errFileSizeLimit         = errors.New("gitdocs: file exceeds max_file_bytes")
	errTotalBytes            = errors.New("gitdocs: total size exceeds max_total_bytes")
	errInvalidUTF8           = errors.New("gitdocs: markdown file is not valid UTF-8")
	errFrontmatter           = errors.New("gitdocs: invalid frontmatter")
	errYAMLAlias             = errors.New("gitdocs: yaml aliases are not allowed in frontmatter")
	errDuplicateID           = errors.New("gitdocs: duplicate document ID")
	errCredentialUnavailable = errors.New("gitdocs: credential unavailable")
	errInvalidCredential     = errors.New("gitdocs: invalid credential")
	errArchiveFetch          = errors.New("gitdocs: archive fetch failed")
	errArchiveSizeLimit      = errors.New("gitdocs: archive exceeds max_archive_bytes")
	errDecompressedLimit     = errors.New("gitdocs: archive exceeds max_decompressed_bytes")
	errInvalidArchive        = errors.New("gitdocs: invalid tar.gz archive")
	errArchivePath           = errors.New("gitdocs: invalid archive entry path")
)

var (
	docIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)
	credentialRefPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	headingPattern       = regexp.MustCompile(`^[ ]{0,3}#{1,4}(?:[\t ]+|$)(.*)$`)
	headingClosing       = regexp.MustCompile(`[\t ]+#+[\t ]*$`)
	fencePattern         = regexp.MustCompile("^[ ]{0,3}(`{3,}|~{3,})(.*)$")
	singleLineClean      = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")
)

func init() { plugin.Register(Module{}) }

// Module implements knowledge.git_markdown.
type Module struct {
	Dir                  string         `yaml:"dir"`
	ArchiveURL           string         `yaml:"archive_url"`
	CredentialRef        string         `yaml:"credential_ref"`
	StripComponents      *int           `yaml:"strip_components"`
	Subdir               string         `yaml:"subdir"`
	RefreshTTL           *time.Duration `yaml:"refresh_ttl"`
	MaxFileBytes         int            `yaml:"max_file_bytes"`
	MaxTotalBytes        int            `yaml:"max_total_bytes"`
	MaxArchiveBytes      int            `yaml:"max_archive_bytes"`
	MaxDecompressedBytes int            `yaml:"max_decompressed_bytes"`
	MaxFiles             int            `yaml:"max_files"`
	MaxEntries           int            `yaml:"max_entries"`

	rt *storeRuntime
}

type storeRuntime struct {
	host      plugin.Host
	refreshMu sync.Mutex
	snap      atomic.Pointer[snapshot]
}

type snapshotDoc struct {
	doc     knowledge.Doc
	content string
}

type snapshot struct {
	loadedAt time.Time
	docs     []knowledge.Doc
	byID     map[string]snapshotDoc
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{
		ID:  moduleID,
		New: func() plugin.Module { return &Module{} },
	}
}

func (m *Module) Validate() error {
	hasDir := strings.TrimSpace(m.Dir) != ""
	hasArchive := strings.TrimSpace(m.ArchiveURL) != ""
	if hasDir == hasArchive {
		return errors.New("gitdocs: exactly one of dir or archive_url is required")
	}
	if hasDir {
		if !utf8.ValidString(m.Dir) || strings.ContainsAny(m.Dir, "\x00\r\n") {
			return errors.New("gitdocs: invalid dir")
		}
		if m.CredentialRef != "" {
			return errors.New("gitdocs: credential_ref is only valid with archive_url")
		}
	}
	if hasArchive {
		if !utf8.ValidString(m.ArchiveURL) || strings.ContainsAny(m.ArchiveURL, "\x00\r\n") {
			return errors.New("gitdocs: invalid archive_url")
		}
		parsed, err := url.Parse(m.ArchiveURL)
		if err != nil || parsed.Host == "" || parsed.User != nil {
			return errors.New("gitdocs: invalid archive_url")
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "http" && scheme != "https" {
			return errors.New("gitdocs: archive_url must use http or https")
		}
		if m.CredentialRef != "" {
			if !credentialRefPattern.MatchString(m.CredentialRef) {
				return errors.New("gitdocs: invalid credential_ref")
			}
			if scheme != "https" {
				return errors.New("gitdocs: archive_url must use https when credential_ref is set")
			}
		}
	}
	if m.StripComponents != nil && (*m.StripComponents < 0 || *m.StripComponents > maxStripComponents) {
		return errors.New("gitdocs: strip_components must be between 0 and 4")
	}
	if _, err := parseSubdir(m.Subdir); err != nil {
		return err
	}
	if m.RefreshTTL != nil {
		if *m.RefreshTTL < 0 || *m.RefreshTTL > maxRefreshTTL {
			return errors.New("gitdocs: refresh_ttl must be between 0 and 1h")
		}
	}
	if m.MaxFileBytes < 0 || m.MaxFileBytes > maxFileBytesLimit {
		return errors.New("gitdocs: max_file_bytes must be between 1 and 1MiB")
	}
	if m.MaxTotalBytes < 0 || m.MaxTotalBytes > maxTotalBytesLimit {
		return errors.New("gitdocs: max_total_bytes must be between 1 and 32MiB")
	}
	if m.MaxArchiveBytes < 0 || m.MaxArchiveBytes > maxArchiveBytesLimit {
		return errors.New("gitdocs: max_archive_bytes must be between 1 and 32MiB")
	}
	if m.MaxDecompressedBytes < 0 || m.MaxDecompressedBytes > maxDecompressedBytesLimit {
		return errors.New("gitdocs: max_decompressed_bytes must be between 1 and 64MiB")
	}
	if m.MaxFiles < 0 || m.MaxFiles > maxFilesLimit {
		return errors.New("gitdocs: max_files must be between 1 and 1000")
	}
	if m.MaxEntries < 0 || m.MaxEntries > maxEntriesLimit {
		return errors.New("gitdocs: max_entries must be between 1 and 20000")
	}
	return nil
}

func parseSubdir(subdir string) ([]string, error) {
	if subdir == "" {
		return nil, nil
	}
	if !utf8.ValidString(subdir) || strings.ContainsAny(subdir, "\\\x00\r\n") || strings.HasPrefix(subdir, "/") {
		return nil, errors.New("gitdocs: invalid subdir")
	}
	trimmed := strings.TrimSuffix(subdir, "/")
	if trimmed == "" {
		return nil, errors.New("gitdocs: invalid subdir")
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) > maxWalkDepth {
		return nil, errDepthLimit
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return nil, errors.New("gitdocs: invalid subdir segment")
		}
	}
	return parts, nil
}

func (m *Module) effectiveRefreshTTL() time.Duration {
	if m.RefreshTTL == nil {
		return defaultRefreshTTL
	}
	return *m.RefreshTTL
}

func (m *Module) effectiveMaxFileBytes() int {
	if m.MaxFileBytes == 0 {
		return defaultMaxFileBytes
	}
	return m.MaxFileBytes
}

func (m *Module) effectiveMaxTotalBytes() int {
	if m.MaxTotalBytes == 0 {
		return defaultMaxTotalBytes
	}
	return m.MaxTotalBytes
}

func (m *Module) effectiveMaxFiles() int {
	if m.MaxFiles == 0 {
		return defaultMaxFiles
	}
	return m.MaxFiles
}

func (m *Module) effectiveMaxEntries() int {
	if m.MaxEntries == 0 {
		return defaultMaxEntries
	}
	return m.MaxEntries
}

func (m *Module) effectiveStripComponents() int {
	if m.StripComponents == nil {
		return defaultStripComponents
	}
	return *m.StripComponents
}

func (m *Module) effectiveMaxArchiveBytes() int {
	if m.MaxArchiveBytes == 0 {
		return defaultMaxArchiveBytes
	}
	return m.MaxArchiveBytes
}

func (m *Module) effectiveMaxDecompressedBytes() int {
	if m.MaxDecompressedBytes == 0 {
		return defaultMaxDecompressedBytes
	}
	return m.MaxDecompressedBytes
}

func (m *Module) Provision(ctx context.Context, h plugin.Host) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rt := &storeRuntime{host: h}
	m.rt = rt
	snap, err := m.loadSnapshot(ctx)
	if err != nil {
		return err
	}
	rt.snap.Store(snap)
	return nil
}

func (m *Module) currentSnapshot(ctx context.Context) (*snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rt := m.rt
	if rt == nil {
		return nil, errors.New("gitdocs: module not provisioned")
	}
	now := rt.host.Now()
	ttl := m.effectiveRefreshTTL()
	if s := rt.snap.Load(); s != nil && (ttl == 0 || now.Sub(s.loadedAt) < ttl) {
		return s, nil
	}
	rt.refreshMu.Lock()
	defer rt.refreshMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now = rt.host.Now()
	if s := rt.snap.Load(); s != nil && (ttl == 0 || now.Sub(s.loadedAt) < ttl) {
		return s, nil
	}
	next, err := m.loadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	rt.snap.Store(next)
	return next, nil
}

func (m *Module) Search(ctx context.Context, q knowledge.SearchQuery) ([]knowledge.Doc, error) {
	snap, err := m.currentSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]knowledge.Doc, 0, len(snap.docs))
	for _, doc := range snap.docs {
		if !matchQuery(doc, q) {
			continue
		}
		out = append(out, cloneDoc(doc))
		if q.MaxDocs > 0 && len(out) >= q.MaxDocs {
			break
		}
	}
	return out, nil
}

func (m *Module) Read(ctx context.Context, id string) (knowledge.ReadResult, error) {
	snap, err := m.currentSnapshot(ctx)
	if err != nil {
		return knowledge.ReadResult{}, err
	}
	item, ok := snap.byID[id]
	if !ok {
		return knowledge.ReadResult{}, knowledge.ErrNotFound
	}
	return knowledge.ReadResult{
		Doc:     cloneDoc(item.doc),
		Content: item.content,
	}, nil
}

type loadState struct {
	maxFileBytes  int
	maxTotalBytes int
	maxFiles      int
	maxEntries    int

	entries    int
	totalBytes int
	byID       map[string]snapshotDoc
}

func (s *loadState) addFile(id string, data []byte) error {
	if !docIDPattern.MatchString(id) || strings.Contains(id, "..") {
		return nil
	}
	if _, exists := s.byID[id]; exists {
		return errDuplicateID
	}
	if len(s.byID) >= s.maxFiles {
		return errFileLimit
	}
	if len(data) > s.maxFileBytes {
		return errFileSizeLimit
	}
	if s.totalBytes+len(data) > s.maxTotalBytes {
		return errTotalBytes
	}
	if !utf8.Valid(data) {
		return errInvalidUTF8
	}
	content := string(data)
	doc, err := parseMarkdown(id, content)
	if err != nil {
		return err
	}
	s.totalBytes += len(data)
	s.byID[id] = snapshotDoc{doc: doc, content: content}
	return nil
}

func (s *loadState) finish(loadedAt time.Time) *snapshot {
	docs := make([]knowledge.Doc, 0, len(s.byID))
	for _, item := range s.byID {
		docs = append(docs, item.doc)
	}
	slices.SortFunc(docs, func(a, b knowledge.Doc) int {
		return cmp.Compare(a.ID, b.ID)
	})
	return &snapshot{
		loadedAt: loadedAt,
		docs:     docs,
		byID:     s.byID,
	}
}

func (m *Module) loadSnapshot(ctx context.Context) (*snapshot, error) {
	subdirParts, err := parseSubdir(m.Subdir)
	if err != nil {
		return nil, err
	}
	state := &loadState{
		maxFileBytes:  m.effectiveMaxFileBytes(),
		maxTotalBytes: m.effectiveMaxTotalBytes(),
		maxFiles:      m.effectiveMaxFiles(),
		maxEntries:    m.effectiveMaxEntries(),
		byID:          make(map[string]snapshotDoc),
	}
	if strings.TrimSpace(m.ArchiveURL) != "" {
		if err := m.loadArchive(ctx, subdirParts, state); err != nil {
			return nil, err
		}
	} else {
		if err := walkDirectory(ctx, m.Dir, subdirParts, state); err != nil {
			return nil, err
		}
	}
	return state.finish(m.rt.host.Now()), nil
}

type archiveCredential struct {
	BearerToken string `json:"bearer_token"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

func (m *Module) applyCredential(req *http.Request) error {
	if m.CredentialRef == "" {
		return nil
	}
	raw, err := m.rt.host.Credential(m.CredentialRef)
	if err != nil {
		return errCredentialUnavailable
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return errInvalidCredential
	}
	if strings.HasPrefix(trimmed, "{") {
		var cred archiveCredential
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cred); err != nil {
			return errInvalidCredential
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return errInvalidCredential
		}
		hasBearer := cred.BearerToken != ""
		hasBasic := cred.Username != "" || cred.Password != ""
		if hasBearer == hasBasic {
			return errInvalidCredential
		}
		if hasBearer {
			if strings.ContainsAny(cred.BearerToken, "\r\n\x00") {
				return errInvalidCredential
			}
			req.Header.Set("Authorization", "Bearer "+cred.BearerToken)
			return nil
		}
		if cred.Username == "" || cred.Password == "" ||
			strings.ContainsAny(cred.Username, "\r\n\x00:") || strings.ContainsAny(cred.Password, "\r\n\x00") {
			return errInvalidCredential
		}
		req.SetBasicAuth(cred.Username, cred.Password)
		return nil
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return errInvalidCredential
	}
	req.Header.Set("Authorization", "Bearer "+trimmed)
	return nil
}

type countingReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.read > c.limit {
		return 0, errDecompressedLimit
	}
	remaining := c.limit - c.read + 1
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read > c.limit {
		return 0, errDecompressedLimit
	}
	return n, err
}

func (m *Module) loadArchive(ctx context.Context, subdirParts []string, state *loadState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.ArchiveURL, nil)
	if err != nil {
		return errArchiveFetch
	}
	if err := m.applyCredential(req); err != nil {
		return err
	}
	resp, err := m.rt.host.HTTPClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errArchiveFetch
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitdocs: archive fetch failed with status %d", resp.StatusCode)
	}

	maxArchiveBytes := m.effectiveMaxArchiveBytes()
	archiveBytes, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxArchiveBytes)+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errArchiveFetch
	}
	if len(archiveBytes) > maxArchiveBytes {
		return errArchiveSizeLimit
	}

	gz, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return errInvalidArchive
	}
	defer gz.Close()

	cr := &countingReader{r: gz, limit: int64(m.effectiveMaxDecompressedBytes())}
	tr := tar.NewReader(cr)
	strip := m.effectiveStripComponents()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, errDecompressedLimit) {
				return errDecompressedLimit
			}
			return errInvalidArchive
		}
		state.entries++
		if state.entries > state.maxEntries {
			return errEntryLimit
		}
		rawParts, err := validateArchivePath(hdr.Name)
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if len(rawParts) <= strip {
			continue
		}
		parts := rawParts[strip:]
		if len(subdirParts) > 0 {
			if len(parts) <= len(subdirParts) || !slices.Equal(parts[:len(subdirParts)], subdirParts) {
				continue
			}
			parts = parts[len(subdirParts):]
		}
		if slices.ContainsFunc(parts, func(seg string) bool { return strings.HasPrefix(seg, ".") }) {
			continue
		}
		if len(parts)-1 > maxWalkDepth {
			return errDepthLimit
		}
		if !strings.HasSuffix(parts[len(parts)-1], ".md") {
			continue
		}
		if hdr.Size < 0 || hdr.Size > int64(state.maxFileBytes) {
			return errFileSizeLimit
		}
		data, err := io.ReadAll(io.LimitReader(tr, int64(state.maxFileBytes)+1))
		if err != nil {
			if errors.Is(err, errDecompressedLimit) {
				return errDecompressedLimit
			}
			return errInvalidArchive
		}
		if len(data) > state.maxFileBytes {
			return errFileSizeLimit
		}
		if err := state.addFile(strings.Join(parts, "/"), data); err != nil {
			return err
		}
	}
	return nil
}

func validateArchivePath(name string) ([]string, error) {
	if name == "" || !utf8.ValidString(name) || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00\r\n") {
		return nil, errArchivePath
	}
	raw := strings.Split(name, "/")
	parts := make([]string, 0, len(raw))
	for _, seg := range raw {
		if seg == ".." {
			return nil, errArchivePath
		}
		if seg == "" || seg == "." {
			continue
		}
		parts = append(parts, seg)
	}
	return parts, nil
}

type frontmatter struct {
	Title       string   `yaml:"title"`
	Summary     string   `yaml:"summary"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

func parseMarkdown(id, content string) (knowledge.Doc, error) {
	body := content
	var fm frontmatter
	if fmText, rest, hasFM := splitFrontmatter(content); hasFM {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(fmText), &node); err != nil {
			return knowledge.Doc{}, errFrontmatter
		}
		if hasYAMLAlias(&node) {
			return knowledge.Doc{}, errYAMLAlias
		}
		if len(node.Content) > 0 {
			if err := node.Decode(&fm); err != nil {
				return knowledge.Doc{}, errFrontmatter
			}
		}
		body = rest
	}
	headings := extractHeadings(body)
	title := normalizeText(fm.Title, maxTitleBytes)
	if title == "" && len(headings) > 0 {
		title = normalizeText(headings[0], maxTitleBytes)
	}
	if title == "" {
		base := strings.TrimSuffix(path.Base(id), ".md")
		title = normalizeText(base, maxTitleBytes)
	}
	if title == "" {
		title = normalizeText(id, maxTitleBytes)
	}
	summary := normalizeText(fm.Summary, maxSummaryBytes)
	if summary == "" {
		summary = normalizeText(fm.Description, maxSummaryBytes)
	}
	var tags []string
	if len(fm.Tags) > 0 {
		seen := make(map[string]bool, len(fm.Tags))
		for _, rawTag := range fm.Tags {
			tag := normalizeText(rawTag, maxTagBytes)
			if tag == "" || seen[tag] {
				continue
			}
			seen[tag] = true
			tags = append(tags, tag)
			if len(tags) >= maxTags {
				break
			}
		}
	}
	return knowledge.Doc{
		ID:       id,
		Title:    title,
		Summary:  summary,
		Tags:     tags,
		Headings: headings,
	}, nil
}

func splitFrontmatter(content string) (fmText, body string, ok bool) {
	firstLine, rest, found := cutLine(content)
	if !found || strings.TrimRight(firstLine, " \t") != "---" {
		return "", content, false
	}
	var fmBuilder strings.Builder
	cur := rest
	for len(cur) > 0 {
		line, next, hasNext := cutLine(cur)
		if strings.TrimRight(line, " \t") == "---" {
			return fmBuilder.String(), next, true
		}
		fmBuilder.WriteString(line)
		fmBuilder.WriteByte('\n')
		if !hasNext {
			break
		}
		cur = next
	}
	return "", content, false
}

func cutLine(s string) (line, rest string, hasNewline bool) {
	idx := strings.IndexByte(s, '\n')
	if idx < 0 {
		return strings.TrimSuffix(s, "\r"), "", false
	}
	return strings.TrimSuffix(s[:idx], "\r"), s[idx+1:], true
}

func hasYAMLAlias(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range node.Content {
		if hasYAMLAlias(child) {
			return true
		}
	}
	return false
}

func extractHeadings(body string) []string {
	var headings []string
	fence := ""
	for line := range strings.Lines(body) {
		line = strings.TrimRight(line, "\r\n")
		if match := fencePattern.FindStringSubmatch(line); match != nil {
			switch {
			case fence == "":
				fence = match[1]
			case strings.HasPrefix(match[1], fence) && strings.TrimSpace(match[2]) == "":
				fence = ""
			}
			continue
		}
		if fence != "" {
			continue
		}
		if match := headingPattern.FindStringSubmatch(line); match != nil {
			text := headingClosing.ReplaceAllString(match[1], "")
			text = normalizeText(text, maxHeadingBytes)
			if text != "" {
				headings = append(headings, text)
				if len(headings) >= maxHeadings {
					break
				}
			}
		}
	}
	return headings
}

func normalizeText(s string, maxBytes int) string {
	s = strings.TrimSpace(singleLineClean.Replace(s))
	if len(s) <= maxBytes {
		return s
	}
	n := maxBytes
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n])
}

func matchQuery(doc knowledge.Doc, q knowledge.SearchQuery) bool {
	for _, wantTag := range q.Tags {
		if !slices.ContainsFunc(doc.Tags, func(tag string) bool {
			return strings.EqualFold(tag, wantTag)
		}) {
			return false
		}
	}
	if q.Query == "" {
		return true
	}
	needle := strings.ToLower(q.Query)
	match := func(s string) bool { return strings.Contains(strings.ToLower(s), needle) }
	return match(doc.ID) || match(doc.Title) || match(doc.Summary) ||
		slices.ContainsFunc(doc.Tags, match) || slices.ContainsFunc(doc.Headings, match)
}

func cloneDoc(doc knowledge.Doc) knowledge.Doc {
	doc.Tags = slices.Clone(doc.Tags)
	doc.Headings = slices.Clone(doc.Headings)
	return doc
}
