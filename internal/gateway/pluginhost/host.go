package pluginhost

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/liubing0806/allowops/internal/redact"
	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/changes"
	"github.com/liubing0806/allowops/plugin/inventory"
	"github.com/liubing0806/allowops/plugin/knowledge"
)

type Deps struct {
	Logger              *slog.Logger
	Hosts               func(context.Context) ([]plugin.HostInfo, error)
	ControlPlaneChanges func(context.Context, time.Time, time.Time, int) ([]plugin.ControlPlaneChange, bool, error)
	Now                 func() time.Time
}

type Host struct {
	instances  []*instance
	redactor   *redact.Redactor
	maxLine    int
	baseCtx    context.Context
	baseCancel context.CancelFunc

	mu       sync.Mutex // serializes registration of calls with the start of Close
	closing  bool
	closed   chan struct{}
	inFlight sync.WaitGroup
}

type instance struct {
	id, module, namespace string
	timeout               time.Duration
	resolver              inventory.Resolver
	lister                changes.Lister
	store                 knowledge.Store
	cleaner               plugin.Cleaner
	ok                    bool
	logger                *slog.Logger
	sem                   chan struct{}
	refs                  atomic.Int64
	client                *http.Client
	credentials           *credentialFiles
}

func (i *instance) acquire() { i.refs.Add(1) }

func (i *instance) release() {
	if i.refs.Add(-1) == 0 {
		i.credentials.close()
		i.client.CloseIdleConnections()
	}
}

type instanceHost struct {
	inst  *instance
	hosts func(context.Context) ([]plugin.HostInfo, error)
	cache *instanceCache
	now   func() time.Time
}

func (h instanceHost) InstanceID() string       { return h.inst.id }
func (h instanceHost) Logger() *slog.Logger     { return h.inst.logger }
func (h instanceHost) HTTPClient() *http.Client { return h.inst.client }
func (h instanceHost) Cache() plugin.Cache      { return h.cache }
func (h instanceHost) Now() time.Time           { return h.now().UTC() }

func (h instanceHost) Credential(ref string) ([]byte, error) {
	return h.inst.credentials.read(ref)
}

func (h instanceHost) Hosts(ctx context.Context) ([]plugin.HostInfo, error) {
	if h.hosts == nil {
		return nil, errors.New("plugin hosts: unavailable")
	}
	return h.hosts(ctx)
}

type controlPlaneHost struct {
	instanceHost
	reader func(context.Context, time.Time, time.Time, int) ([]plugin.ControlPlaneChange, bool, error)
}

func (h controlPlaneHost) ListControlPlaneChanges(ctx context.Context, from, to time.Time, limit int) ([]plugin.ControlPlaneChange, bool, error) {
	if from.IsZero() || to.Before(from) || to.Sub(from) > 7*24*time.Hour || limit < 1 || limit > 1000 {
		return nil, false, errors.New("plugin control plane changes: invalid query")
	}
	return h.reader(ctx, from.UTC(), to.UTC(), limit)
}

// Query is the caller's search. Name is a case-insensitive substring matched
// against the redacted entity name.
type Query struct {
	Kind, Name string
}

type Result struct {
	inventory.Entity
	Source            string                       `json:"Source,omitempty"`
	Sources           []string                     `json:"Sources,omitempty"`
	HostCount         int                          `json:"HostCount,omitempty"`
	Conflicts         map[string]map[string]string `json:"Conflicts,omitempty"`
	SelectorConflicts map[string]string            `json:"SelectorConflicts,omitempty"`

	rawKind, rawName string
	secrets          []string
}

type SourceError struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type Health struct {
	ID, Module string
	OK         bool
}

var (
	instanceID  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	attrPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

func validEntity(e inventory.Entity) bool {
	if !kindPattern.MatchString(e.Kind) || len(e.Name) == 0 || len(e.Name) > 128 || len(e.Selector) > 512 {
		return false
	}
	values := []string{e.Name, e.Selector}
	values = append(values, e.Hosts...)
	values = append(values, e.DependsOn...)
	for k, v := range e.Attrs {
		if !attrPattern.MatchString(k) {
			return false
		}
		values = append(values, v)
	}
	for _, v := range values {
		if strings.ContainsAny(v, "\r\n") {
			return false
		}
	}
	return true
}

func New(ctx context.Context, configs []Config, deps Deps) (_ *Host, startupErr error) {
	if len(configs) > 32 {
		return nil, errors.New("plugins: at most 32 instances allowed")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	baseCtx, baseCancel := context.WithCancel(context.WithoutCancel(ctx))
	redactor, _ := redact.New(nil)
	h := &Host{redactor: redactor, maxLine: redact.DefaultMaxLine, baseCtx: baseCtx, baseCancel: baseCancel, closed: make(chan struct{})}
	defer func() {
		if startupErr != nil {
			shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			h.Close(shutdown)
		}
	}()
	seen := make(map[string]bool)
	for position, c := range configs {
		// Only a validated instance ID can appear in startup errors.
		if !instanceID.MatchString(c.ID) || seen[c.ID] {
			return nil, fmt.Errorf("plugins[%d]: invalid or duplicate instance ID", position)
		}
		seen[c.ID] = true
		if c.Timeout == 0 {
			c.Timeout = 5 * time.Second
		}
		if c.Timeout < 100*time.Millisecond || c.Timeout > 30*time.Second {
			return nil, fmt.Errorf("plugin %s: timeout must be 100ms~30s", c.ID)
		}
		if c.MaxConcurrency == 0 {
			c.MaxConcurrency = 4
		}
		if c.MaxConcurrency < 1 || c.MaxConcurrency > 32 {
			return nil, fmt.Errorf("plugin %s: max_concurrency must be 1~32", c.ID)
		}
		if err := validateCredentials(c); err != nil {
			return nil, fmt.Errorf("plugin %s: %w", c.ID, err)
		}
		if c.Disabled {
			if _, err := egressConfig(c); err != nil {
				return nil, fmt.Errorf("plugin %s: %w", c.ID, err)
			}
			continue
		}
		inst, err := h.newInstance(ctx, c, deps)
		if err != nil {
			return nil, err
		}
		h.instances = append(h.instances, inst)
	}
	return h, nil
}

func (h *Host) newInstance(ctx context.Context, c Config, deps Deps) (*instance, error) {
	info, found := plugin.Lookup(plugin.ModuleID(c.Module))
	if !found {
		return nil, fmt.Errorf("plugin %s: unknown module", c.ID)
	}
	m := info.New()
	namespace, _, _ := strings.Cut(c.Module, ".")
	inst := &instance{id: c.ID, module: c.Module, namespace: namespace, timeout: c.Timeout, sem: make(chan struct{}, c.MaxConcurrency)}
	switch namespace {
	case "inventory":
		inst.resolver, _ = m.(inventory.Resolver)
	case "changes":
		inst.lister, _ = m.(changes.Lister)
	case "knowledge":
		inst.store, _ = m.(knowledge.Store)
	}
	if inst.resolver == nil && inst.lister == nil && inst.store == nil {
		return nil, fmt.Errorf("plugin %s: module does not implement its namespace interface", c.ID)
	}
	if err := decodeConfig(c, m); err != nil {
		return nil, err
	}
	if v, ok := m.(plugin.Validator); ok {
		if err := invoke(v.Validate); err != nil {
			return nil, fmt.Errorf("plugin %s: validate: %s", c.ID, h.safe(err))
		}
	}
	client, err := newEgressClient(c, nil)
	if err != nil {
		return nil, fmt.Errorf("plugin %s: %w", c.ID, err)
	}
	credentials, err := newCredentialFiles(c)
	if err != nil {
		client.CloseIdleConnections()
		return nil, fmt.Errorf("plugin %s: %w", c.ID, err)
	}
	inst.client, inst.credentials = client, credentials
	inst.logger = slog.New(redactingHandler{Handler: deps.Logger.Handler(), redactor: h.redactor}).With("plugin", c.ID)
	inst.cleaner, _ = m.(plugin.Cleaner)
	inst.refs.Store(1)
	host := instanceHost{inst: inst, hosts: deps.Hosts, cache: newInstanceCache(deps.Now), now: deps.Now}
	var capability plugin.Host = host
	if c.Module == "changes.allowops" && deps.ControlPlaneChanges != nil {
		capability = controlPlaneHost{instanceHost: host, reader: deps.ControlPlaneChanges}
	}
	if p, ok := m.(plugin.Provisioner); ok {
		if err := inst.provision(ctx, p, capability); err != nil {
			inst.release()
			if c.Required {
				return nil, fmt.Errorf("plugin %s: provision: %s", c.ID, h.safe(err))
			}
			inst.logger.Error("provision failed", "error", err)
			return inst, nil
		}
	}
	inst.ok = true
	return inst, nil
}

func invoke(fn func() error) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("plugin panic: %v", value)
		}
	}()
	return fn()
}

func (i *instance) provision(ctx context.Context, p plugin.Provisioner, host plugin.Host) error {
	callCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	done := make(chan error)
	abandoned := make(chan struct{})
	i.acquire()
	go func() {
		defer i.release()
		err := invoke(func() error { return p.Provision(callCtx, host) })
		// The unbuffered result hands cleanup ownership to exactly one side.
		select {
		case done <- err:
		case <-abandoned:
			i.cleanup(context.WithoutCancel(ctx))
		}
	}()
	select {
	case err := <-done:
		if callCtx.Err() != nil {
			err = callCtx.Err()
		}
		if err != nil {
			i.cleanup(context.WithoutCancel(ctx))
		}
		return err
	case <-callCtx.Done():
		close(abandoned)
		return callCtx.Err()
	}
}

func (i *instance) cleanup(ctx context.Context) {
	if i.cleaner == nil {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, min(i.timeout, time.Second))
	defer cancel()
	done := make(chan struct{})
	i.acquire()
	go func() {
		defer close(done)
		defer i.release()
		if err := invoke(func() error { return i.cleaner.Cleanup(cleanupCtx) }); err != nil {
			i.logger.Error("cleanup failed", "error", err)
		}
	}()
	select {
	case <-done:
	case <-cleanupCtx.Done():
	}
}

func (h *Host) Close(ctx context.Context) {
	h.mu.Lock()
	if !h.closing {
		h.closing = true
		h.baseCancel()
		go h.shutdown(ctx)
	}
	h.mu.Unlock()

	select {
	case <-h.closed:
	case <-ctx.Done():
	}
}

func (h *Host) shutdown(ctx context.Context) {
	defer close(h.closed)
	drained := make(chan struct{})
	go func() {
		h.inFlight.Wait()
		close(drained)
	}()
	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	select {
	case <-drained:
	case <-drainCtx.Done():
	}
	cancel()

	// Cleanup retains its own bounded context after the caller's drain
	// deadline; the caller can return while shutdown still owns resources.
	cleanupCtx := context.WithoutCancel(ctx)
	for index := len(h.instances) - 1; index >= 0; index-- {
		inst := h.instances[index]
		if inst.ok {
			inst.cleanup(cleanupCtx)
			inst.release()
		}
	}
}

func (h *Host) InventorySources() []string { return h.sourceIDs("inventory") }
func (h *Host) ChangesSources() []string   { return h.sourceIDs("changes") }
func (h *Host) KnowledgeSources() []string { return h.sourceIDs("knowledge") }

func (h *Host) sourceIDs(namespace string) []string {
	var ids []string
	for _, inst := range h.instances {
		if inst.ok && inst.namespace == namespace {
			ids = append(ids, inst.id)
		}
	}
	return ids
}

func (h *Host) Health() []Health {
	out := make([]Health, 0, len(h.instances))
	for _, inst := range h.instances {
		out = append(out, Health{ID: inst.id, Module: inst.module, OK: inst.ok})
	}
	return out
}

type redactingHandler struct {
	slog.Handler
	redactor *redact.Redactor
}

var singleLine = strings.NewReplacer("\r", " ", "\n", " ")

func (h redactingHandler) line(s string) string { return h.redactor.Line(singleLine.Replace(s)) }

func (h redactingHandler) attr(attr slog.Attr) slog.Attr {
	attr.Key = h.line(attr.Key)
	attr.Value = attr.Value.Resolve()
	switch attr.Value.Kind() {
	case slog.KindString:
		attr.Value = slog.StringValue(h.attrText(attr.Key, attr.Value.String()))
	case slog.KindAny:
		if err, ok := attr.Value.Any().(error); ok {
			attr.Value = slog.StringValue(h.attrText(attr.Key, err.Error()))
		}
	case slog.KindGroup:
		attr.Value = slog.GroupValue(h.attrs(attr.Value.Group())...)
	}
	return attr
}

func (h redactingHandler) attrText(key, value string) string {
	value = singleLine.Replace(value)
	prefix := key + "="
	clean := h.redactor.Line(prefix + value)
	if !strings.HasPrefix(clean, prefix) {
		return "[REDACTED]"
	}
	return h.line(strings.TrimPrefix(clean, prefix))
}

func (h redactingHandler) attrs(attrs []slog.Attr) []slog.Attr {
	clean := make([]slog.Attr, len(attrs))
	for i, attr := range attrs {
		clean[i] = h.attr(attr)
	}
	return clean
}

func (h redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	clean := slog.NewRecord(record.Time, record.Level, h.line(record.Message), record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		clean.AddAttrs(h.attr(attr))
		return true
	})
	return h.Handler.Handle(ctx, clean)
}

func (h redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.Handler = h.Handler.WithAttrs(h.attrs(attrs))
	return h
}

func (h redactingHandler) WithGroup(name string) slog.Handler {
	h.Handler = h.Handler.WithGroup(h.line(name))
	return h
}

func (h *Host) safe(v any) string {
	return h.redactor.Line(singleLine.Replace(fmt.Sprint(v)))
}

type callResult[T any] struct {
	value  T
	reason string
	err    error
}

func pluginCall[T any](ctx context.Context, h *Host, i *instance, fn func(context.Context) (T, error)) callResult[T] {
	callCtx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		return callResult[T]{reason: "closed"}
	}
	h.inFlight.Add(1)
	i.acquire()
	h.mu.Unlock()
	stop := context.AfterFunc(h.baseCtx, cancel)
	defer stop()

	select {
	case i.sem <- struct{}{}:
		if callCtx.Err() != nil {
			<-i.sem
			i.release()
			h.inFlight.Done()
			return callResult[T]{reason: "timeout"}
		}
	case <-callCtx.Done():
		i.release()
		h.inFlight.Done()
		return callResult[T]{reason: "timeout"}
	}

	done := make(chan callResult[T], 1)
	go func() {
		defer h.inFlight.Done()
		defer i.release()
		defer func() { <-i.sem }()
		var result callResult[T]
		defer func() {
			if value := recover(); value != nil {
				i.logger.Error("plugin call panic", "panic", fmt.Sprint(value))
				result = callResult[T]{reason: "panic"}
			}
			done <- result
		}()
		result.value, result.err = fn(callCtx)
		if result.err != nil {
			if !errors.Is(result.err, knowledge.ErrNotFound) {
				i.logger.Error("plugin call failed", "error", result.err)
			}
			result.reason = "failed"
		}
	}()
	select {
	case result := <-done:
		if callCtx.Err() == nil {
			return result
		}
	case <-callCtx.Done():
	}
	return callResult[T]{reason: "timeout"}
}

type sourceCall[T any] struct {
	inst *instance
	done <-chan callResult[T]
}

func sourceCalls[T any](ctx context.Context, h *Host, namespace string, sources []string, fn func(context.Context, *instance) (T, error)) []sourceCall[T] {
	var calls []sourceCall[T]
	for _, inst := range h.instances {
		if !inst.ok || inst.namespace != namespace || len(sources) > 0 && !slices.Contains(sources, inst.id) {
			continue
		}
		done := make(chan callResult[T], 1)
		calls = append(calls, sourceCall[T]{inst, done})
		go func() {
			done <- pluginCall(ctx, h, inst, func(ctx context.Context) (T, error) { return fn(ctx, inst) })
		}()
	}
	return calls
}

func (h *Host) SearchInventory(ctx context.Context, q Query, sources []string) ([]Result, []SourceError) {
	results, sourceErrors := h.SearchInventoryForMerge(ctx, q, sources)
	return slices.DeleteFunc(results, func(e Result) bool {
		return !containsFold(e.Name, q.Name)
	}), sourceErrors
}

// SearchInventoryForMerge leaves Name filtering to MergeVisibleInventory so
// only entities visible to the caller can influence public names.
func (h *Host) SearchInventoryForMerge(ctx context.Context, q Query, sources []string) ([]Result, []SourceError) {
	calls := sourceCalls(ctx, h, "inventory", sources, func(ctx context.Context, inst *instance) ([]inventory.Entity, error) {
		return inst.resolver.Resolve(ctx, inventory.Query{Kind: q.Kind})
	})
	results := []Result{}
	sourceErrors := []SourceError{}
	for _, call := range calls {
		result := <-call.done
		if result.reason != "" {
			sourceErrors = append(sourceErrors, SourceError{call.inst.id, result.reason})
			continue
		}
		discarded := 0
		seen := make(map[[2]string]bool)
		for _, e := range result.value {
			if !validEntity(e) {
				discarded++
				continue
			}
			if q.Kind != "" && e.Kind != q.Kind {
				continue
			}
			key := [2]string{e.Kind, e.Name}
			if seen[key] {
				discarded++
				continue
			}
			seen[key] = true
			e = cloneEntity(e)
			secrets := h.redactEntity(&e)
			results = append(results, Result{Entity: e, Source: call.inst.id, rawKind: key[0], rawName: key[1], secrets: secrets})
		}
		if discarded > 0 {
			call.inst.logger.Warn("invalid or duplicate inventory entities discarded", "count", discarded)
		}
	}
	sortInventory(results)
	return results, sourceErrors
}

func cloneEntity(e inventory.Entity) inventory.Entity {
	e.Attrs = maps.Clone(e.Attrs)
	e.Hosts = slices.Clone(e.Hosts)
	e.DependsOn = slices.Clone(e.DependsOn)
	return e
}

func sortInventory(results []Result) {
	slices.SortStableFunc(results, func(a, b Result) int {
		if n := strings.Compare(a.Kind, b.Kind); n != 0 {
			return n
		}
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return strings.Compare(firstSource(a), firstSource(b))
	})
}

func firstSource(e Result) string {
	if len(e.Sources) > 0 {
		return e.Sources[0]
	}
	return e.Source
}

func containsFold(text, query string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(query))
}

// MergeVisibleInventory accepts per-source results after caller visibility
// checks. Original identities and secrets are discarded from the merged output.
func MergeVisibleInventory(visible []Result, nameFilter string) []Result {
	secrets := make(map[[2]string][]string)
	for _, row := range visible {
		key := rawIdentity(row)
		secrets[key] = append(secrets[key], row.secrets...)
	}
	output := []Result{}
	groups := make(map[[2]string][]Result)
	for _, row := range visible {
		e := cloneEntity(row.Entity)
		maskEntitySecrets(&e, secrets[rawIdentity(row)])
		if !containsFold(e.Name, nameFilter) {
			continue
		}
		clean := Result{Entity: e, Source: row.Source}
		if strings.Contains(e.Name, "[REDACTED") {
			output = append(output, mergeInventoryGroup([]Result{clean}))
			continue
		}
		key := [2]string{e.Kind, e.Name}
		groups[key] = append(groups[key], clean)
	}
	for _, group := range groups {
		output = append(output, mergeInventoryGroup(group))
	}
	sortInventory(output)
	return output
}

func rawIdentity(row Result) [2]string {
	if row.rawKind == "" {
		return [2]string{row.Kind, row.Name}
	}
	return [2]string{row.rawKind, row.rawName}
}

func mergeInventoryGroup(group []Result) Result {
	attrValues := make(map[string]map[string]string)
	selectors := make(map[string]string)
	var hosts, depends, sources []string
	for _, row := range group {
		sources = append(sources, row.Source)
		hosts = append(hosts, row.Hosts...)
		depends = append(depends, row.DependsOn...)
		selectors[row.Source] = row.Selector
		for k, v := range row.Attrs {
			if attrValues[k] == nil {
				attrValues[k] = make(map[string]string)
			}
			attrValues[k][row.Source] = v
		}
	}
	hosts, depends, sources = sortedUnique(hosts), sortedUnique(depends), sortedUnique(sources)
	result := Result{
		Entity: inventory.Entity{
			Kind: group[0].Kind, Name: group[0].Name, Hosts: hosts, DependsOn: depends,
		},
		HostCount: len(hosts),
		Sources:   sources,
	}
	if len(sources) == 1 {
		result.Source = sources[0]
	}
	for k, values := range attrValues {
		if value, consistent := commonValue(values); consistent {
			if result.Attrs == nil {
				result.Attrs = make(map[string]string)
			}
			result.Attrs[k] = value
		} else {
			if result.Conflicts == nil {
				result.Conflicts = make(map[string]map[string]string)
			}
			result.Conflicts[k] = values
		}
	}
	if value, consistent := commonValue(selectors); consistent {
		result.Selector = value
	} else {
		result.SelectorConflicts = selectors
	}
	return result
}

func commonValue(values map[string]string) (string, bool) {
	var first string
	set := false
	for _, value := range values {
		if set && value != first {
			return "", false
		}
		first, set = value, true
	}
	return first, set
}

func sortedUnique(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

// redactEntity uses attribute and selector keys as context when recognizing
// credentials, then suppresses copies across the entity's public fields.
func (h *Host) redactEntity(e *inventory.Entity) []string {
	var secrets []string
	redactField := func(value string) string {
		clean, found := h.redactor.LineSecrets(value)
		secrets = append(secrets, found...)
		return clean
	}
	for k, v := range e.Attrs {
		if redactField(k) != k {
			delete(e.Attrs, k)
			if v != "" {
				secrets = append(secrets, v)
			}
			continue
		}
		prefix := k + "="
		keyValue := redactField(prefix + v)
		value := redactField(v)
		if !strings.HasPrefix(keyValue, prefix) {
			if v != "" {
				secrets = append(secrets, v)
			}
			value = "[REDACTED]"
		} else if value == v {
			value = strings.TrimPrefix(keyValue, prefix)
		}
		e.Attrs[k] = value
	}
	e.Name = redactField(e.Name)
	discardSelector := redactField(e.Selector) != e.Selector
	for _, term := range strings.Split(e.Selector, ",") {
		key, value, _ := strings.Cut(term, "=")
		for _, part := range []string{strings.TrimSpace(term), strings.TrimSpace(key), strings.TrimSpace(value)} {
			if redactField(part) != part {
				discardSelector = true
			}
		}
	}
	if discardSelector {
		e.Selector = ""
	}
	for i, v := range e.DependsOn {
		clean := redactField(v)
		if kind, name, ok := strings.Cut(v, "/"); ok && clean == v {
			clean = kind + "/" + redactField(name)
		}
		e.DependsOn[i] = clean
	}
	secrets = sortedUnique(secrets)
	maskEntitySecrets(e, secrets)
	return secrets
}

func holdsSecret(text string, secrets []string) bool {
	return slices.ContainsFunc(secrets, func(secret string) bool { return strings.Contains(text, secret) })
}

func maskEntitySecrets(e *inventory.Entity, secrets []string) {
	for k, v := range e.Attrs {
		if holdsSecret(k, secrets) {
			delete(e.Attrs, k)
		} else if holdsSecret(v, secrets) {
			e.Attrs[k] = "[REDACTED]"
		}
	}
	if holdsSecret(e.Name, secrets) {
		e.Name = "[REDACTED]"
	}
	if holdsSecret(e.Selector, secrets) {
		e.Selector = ""
	}
	for i, v := range e.DependsOn {
		if holdsSecret(v, secrets) {
			e.DependsOn[i] = "[REDACTED]"
		}
	}
}

const maxSourceItems = 1000

type ChangesQuery struct {
	From, To time.Time
	Services []string
}

type ChangeResult struct {
	changes.Change
	Source string
}

func (h *Host) ListChanges(ctx context.Context, q ChangesQuery, sources []string) ([]ChangeResult, bool, []SourceError) {
	query := changes.Query{From: q.From.UTC(), To: q.To.UTC(), MaxItems: maxSourceItems}
	calls := sourceCalls(ctx, h, "changes", sources, func(ctx context.Context, inst *instance) (changes.ListResult, error) {
		return inst.lister.List(ctx, query)
	})
	results := []ChangeResult{}
	sourceErrors := []SourceError{}
	hasMore := false
	for _, call := range calls {
		result := <-call.done
		if result.reason != "" {
			sourceErrors = append(sourceErrors, SourceError{call.inst.id, result.reason})
			continue
		}
		items := result.value.Changes
		hasMore = hasMore || result.value.HasMore || len(items) > maxSourceItems
		discarded := 0
		for _, item := range items[:min(len(items), maxSourceItems)] {
			if item.At.IsZero() || item.At.Before(query.From) || item.At.After(query.To) || !validChange(item) {
				discarded++
				continue
			}
			secrets := h.redactFields(&item.Service, &item.Summary, &item.Actor, &item.Ref)
			if holdsSecret(item.Kind, secrets) {
				discarded++
				continue
			}
			if len(q.Services) > 0 && !slices.ContainsFunc(q.Services, func(service string) bool { return strings.EqualFold(item.Service, service) }) {
				continue
			}
			item.At = item.At.UTC()
			results = append(results, ChangeResult{item, call.inst.id})
		}
		if discarded > 0 {
			call.inst.logger.Warn("invalid changes discarded", "count", discarded)
		}
	}
	slices.SortStableFunc(results, compareChanges)
	return results, hasMore, sourceErrors
}

func validChange(item changes.Change) bool {
	return kindPattern.MatchString(item.Kind) && validField(item.Service, 0, 128) &&
		validField(item.Summary, 1, 512) && validField(item.Actor, 0, 128) && validField(item.Ref, 0, 256)
}

func validField(s string, minBytes, maxBytes int) bool {
	return len(s) >= minBytes && len(s) <= maxBytes && utf8.ValidString(s) && !strings.ContainsAny(s, "\r\n")
}

func compareChanges(a, b ChangeResult) int {
	if n := b.At.Compare(a.At); n != 0 {
		return n
	}
	return slices.Compare(
		[]string{a.Source, a.Kind, a.Service, a.Actor, a.Ref, a.Summary},
		[]string{b.Source, b.Kind, b.Service, b.Actor, b.Ref, b.Summary},
	)
}

// redactFields collects credentials across one record before applying any
// fragment to other fields.
func (h *Host) redactFields(fields ...*string) []string {
	var secrets []string
	for _, field := range fields {
		clean, found := h.redactor.LineSecrets(*field)
		*field = clean
		secrets = append(secrets, found...)
	}
	if len(secrets) > 0 {
		secrets = sortedUnique(secrets)
		scrub := secretReplacer(secrets)
		for _, field := range fields {
			*field = scrub.Replace(*field)
		}
	}
	return secrets
}

func secretReplacer(secrets []string) *strings.Replacer {
	ordered := slices.Clone(secrets)
	slices.SortStableFunc(ordered, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	pairs := make([]string, 0, 2*len(ordered))
	for _, secret := range ordered {
		pairs = append(pairs, secret, "[REDACTED]")
	}
	return strings.NewReplacer(pairs...)
}

type KnowledgeQuery struct {
	Query string
	Tags  []string
}

type KnowledgeDocResult struct {
	knowledge.Doc
	Source string
}

type KnowledgeReadResult struct {
	KnowledgeDocResult
	Content  string
	Revision string
	Sections []KnowledgeSection
}

// KnowledgeSection identifies an ATX heading and its byte offset in Content.
type KnowledgeSection struct {
	Title  string
	Offset int
}

var docIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)

func (h *Host) publicDocID(id string) bool {
	return docIDPattern.MatchString(id) && !strings.Contains(id, "..") && h.redactor.Line(id) == id
}

func (h *Host) sanitizeDoc(doc knowledge.Doc) (knowledge.Doc, []string, bool) {
	if !h.publicDocID(doc.ID) || !validField(doc.Title, 1, 256) || !validField(doc.Summary, 0, 512) ||
		len(doc.Tags) > 32 || len(doc.Headings) > 50 {
		return knowledge.Doc{}, nil, false
	}
	doc.Tags = slices.Clone(doc.Tags)
	doc.Headings = slices.Clone(doc.Headings)
	fields := []*string{&doc.Title, &doc.Summary}
	for i := range doc.Tags {
		if !validField(doc.Tags[i], 1, 64) {
			return knowledge.Doc{}, nil, false
		}
		fields = append(fields, &doc.Tags[i])
	}
	for i := range doc.Headings {
		if !validField(doc.Headings[i], 1, 128) {
			return knowledge.Doc{}, nil, false
		}
		fields = append(fields, &doc.Headings[i])
	}
	secrets := h.redactFields(fields...)
	if holdsSecret(doc.ID, secrets) {
		return knowledge.Doc{}, nil, false
	}
	return doc, secrets, true
}

func (h *Host) SearchKnowledge(ctx context.Context, q KnowledgeQuery, sources []string) ([]KnowledgeDocResult, string, []SourceError) {
	calls := sourceCalls(ctx, h, "knowledge", sources, func(ctx context.Context, inst *instance) ([]knowledge.Doc, error) {
		return inst.store.Search(ctx, knowledge.SearchQuery{MaxDocs: maxSourceItems})
	})
	docs := []KnowledgeDocResult{}
	sourceErrors := []SourceError{}
	for _, call := range calls {
		result := <-call.done
		if result.reason != "" {
			sourceErrors = append(sourceErrors, SourceError{call.inst.id, result.reason})
			continue
		}
		for _, doc := range result.value[:min(len(result.value), maxSourceItems)] {
			if clean, _, ok := h.sanitizeDoc(doc); ok {
				docs = append(docs, KnowledgeDocResult{clean, call.inst.id})
			}
		}
	}
	slices.SortStableFunc(docs, func(a, b KnowledgeDocResult) int {
		if n := strings.Compare(a.Source, b.Source); n != 0 {
			return n
		}
		return strings.Compare(a.ID, b.ID)
	})
	index, _ := json.Marshal(docs) // The index only includes strings and slices of strings.
	revision := contentRevision(index)
	docs = slices.DeleteFunc(docs, func(doc KnowledgeDocResult) bool { return !matchDoc(doc.Doc, q) })
	return docs, revision, sourceErrors
}

func matchDoc(doc knowledge.Doc, q KnowledgeQuery) bool {
	for _, tag := range q.Tags {
		if !slices.ContainsFunc(doc.Tags, func(value string) bool { return strings.EqualFold(value, tag) }) {
			return false
		}
	}
	match := func(s string) bool { return containsFold(s, q.Query) }
	return match(doc.ID) || match(doc.Title) || match(doc.Summary) ||
		slices.ContainsFunc(doc.Tags, match) || slices.ContainsFunc(doc.Headings, match)
}

const maxKnowledgeContent = 1 << 20

func (h *Host) ReadKnowledge(ctx context.Context, source, id string) (KnowledgeReadResult, error) {
	if !h.publicDocID(id) {
		return KnowledgeReadResult{}, knowledge.ErrNotFound
	}
	for _, inst := range h.instances {
		if !inst.ok || inst.namespace != "knowledge" || inst.id != source {
			continue
		}
		result := pluginCall(ctx, h, inst, func(ctx context.Context) (knowledge.ReadResult, error) {
			return inst.store.Read(ctx, id)
		})
		if result.reason != "" {
			if errors.Is(result.err, knowledge.ErrNotFound) {
				return KnowledgeReadResult{}, knowledge.ErrNotFound
			}
			return KnowledgeReadResult{}, errors.New("plugin knowledge: read " + result.reason)
		}
		doc, secrets, ok := h.sanitizeDoc(result.value.Doc)
		if !ok || doc.ID != id {
			return KnowledgeReadResult{}, knowledge.ErrNotFound
		}
		raw := result.value.Content
		if len(raw) > maxKnowledgeContent || !utf8.ValidString(raw) {
			return KnowledgeReadResult{}, errors.New("plugin knowledge: invalid document content")
		}
		var clean bytes.Buffer
		if err := h.redactor.Stream(strings.NewReader(raw), &clean, h.maxLine); err != nil {
			return KnowledgeReadResult{}, errors.New("plugin knowledge: document redaction failed")
		}
		content := clean.String()
		if len(secrets) > 0 {
			content = secretReplacer(secrets).Replace(content)
		}
		return KnowledgeReadResult{
			KnowledgeDocResult: KnowledgeDocResult{doc, source},
			Content:            content,
			Revision:           contentRevision([]byte(content)),
			Sections:           documentSections(content),
		}, nil
	}
	return KnowledgeReadResult{}, knowledge.ErrNotFound
}

func contentRevision(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:8])
}

var (
	markdownHeading = regexp.MustCompile(`^[ ]{0,3}#{1,6}(?:[\t ]+|$)(.*)$`)
	headingClosing  = regexp.MustCompile(`[\t ]+#+[\t ]*$`)
	markdownFence   = regexp.MustCompile("^[ ]{0,3}(`{3,}|~{3,})(.*)$")
)

func documentSections(content string) []KnowledgeSection {
	assigned := make(map[string]bool)
	sections := []KnowledgeSection{}
	offset := 0
	fence := ""
	for line := range strings.Lines(content) {
		sectionOffset := offset
		offset += len(line)
		line = strings.TrimRight(line, "\r\n")
		if match := markdownFence.FindStringSubmatch(line); match != nil {
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
		if heading := markdownHeading.FindStringSubmatch(line); heading != nil {
			title := strings.TrimSpace(headingClosing.ReplaceAllString(heading[1], ""))
			suffix := fmt.Sprintf(" (#%d)", len(sections)+1)
			for assigned[title] {
				title += suffix
			}
			assigned[title] = true
			sections = append(sections, KnowledgeSection{title, sectionOffset})
		}
	}
	return sections
}
