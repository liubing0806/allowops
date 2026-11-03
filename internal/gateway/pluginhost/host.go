package pluginhost

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/redact"
	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/inventory"
)

type Deps struct {
	Logger *slog.Logger
	Hosts  func(context.Context) ([]plugin.HostInfo, error)
}

type Host struct {
	instances []instance
	redactor  *redact.Redactor
}

type instance struct {
	id, module string
	timeout    time.Duration
	resolver   inventory.Resolver
	ok         bool
	logger     *slog.Logger
}

type instanceHost struct {
	id   string
	deps Deps
}

func (h instanceHost) InstanceID() string                                   { return h.id }
func (h instanceHost) Logger() *slog.Logger                                 { return h.deps.Logger }
func (h instanceHost) Hosts(ctx context.Context) ([]plugin.HostInfo, error) { return h.deps.Hosts(ctx) }

// Query is the caller's search. Name is a case-insensitive substring matched
// against the redacted entity name.
type Query struct {
	Kind, Name string
}

type Result struct {
	inventory.Entity
	Source string
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

func New(ctx context.Context, configs []Config, deps Deps) (*Host, error) {
	if len(configs) > 32 {
		return nil, fmt.Errorf("plugins: at most 32 instances allowed")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	h := &Host{}
	h.redactor, _ = redact.New(nil)
	seen := map[string]bool{}
	for _, c := range configs {
		if !instanceID.MatchString(c.ID) || seen[c.ID] {
			return nil, fmt.Errorf("plugin %q: invalid or duplicate instance ID", c.ID)
		}
		seen[c.ID] = true
		if c.Timeout == 0 {
			c.Timeout = 5 * time.Second
		}
		if c.Timeout < 100*time.Millisecond || c.Timeout > 30*time.Second {
			return nil, fmt.Errorf("plugin %s: timeout must be 100ms~30s", c.ID)
		}
		if c.Disabled {
			continue
		}
		info, ok := plugin.Lookup(plugin.ModuleID(c.Module))
		if !ok {
			return nil, fmt.Errorf("plugin %s: unknown module %q", c.ID, c.Module)
		}
		m := info.New()
		resolver, ok := m.(inventory.Resolver)
		if strings.Split(c.Module, ".")[0] != "inventory" || !ok {
			return nil, fmt.Errorf("plugin %s: module %s must implement inventory.Resolver in the inventory namespace", c.ID, c.Module)
		}
		if err := decodeConfig(c, m); err != nil {
			return nil, err
		}
		logger := deps.Logger.With("plugin", c.ID)
		inst := instance{id: c.ID, module: c.Module, timeout: c.Timeout, resolver: resolver, ok: true, logger: logger}
		if p, ok := m.(plugin.Provisioner); ok {
			callCtx, cancel := context.WithTimeout(ctx, c.Timeout)
			err := p.Provision(callCtx, instanceHost{id: c.ID, deps: Deps{Logger: logger, Hosts: deps.Hosts}})
			cancel()
			if err != nil {
				if c.Required {
					return nil, fmt.Errorf("plugin %s: provision: %s", c.ID, h.safe(err))
				}
				inst.ok = false
				logger.Error("provision failed", "error", h.safe(err))
			}
		}
		h.instances = append(h.instances, inst)
	}
	return h, nil
}

func (h *Host) InventorySources() []string {
	var ids []string
	for _, inst := range h.instances {
		if inst.ok {
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

type resolved struct {
	entities []inventory.Entity
	reason   string
}

// safe returns v as one redacted line for logs and startup errors.
func (h *Host) safe(v any) string {
	return h.redactor.Line(strings.NewReplacer("\r", " ", "\n", " ").Replace(fmt.Sprint(v)))
}

func (h *Host) resolve(ctx context.Context, inst instance, q inventory.Query) resolved {
	ctx, cancel := context.WithTimeout(ctx, inst.timeout)
	defer cancel()
	done := make(chan resolved, 1)
	go func() {
		result := resolved{}
		defer func() {
			if value := recover(); value != nil {
				inst.logger.Error("resolve panic", "panic", h.safe(value))
				result = resolved{reason: "panic"}
			}
			done <- result
		}()
		entities, err := inst.resolver.Resolve(ctx, q)
		if err != nil {
			inst.logger.Error("resolve failed", "error", h.safe(err))
			result.reason = "failed"
			return
		}
		result.entities = make([]inventory.Entity, len(entities))
		for i, e := range entities {
			e.Attrs = maps.Clone(e.Attrs)
			e.Hosts = slices.Clone(e.Hosts)
			e.DependsOn = slices.Clone(e.DependsOn)
			result.entities[i] = e
		}
	}()
	select {
	case result := <-done:
		if ctx.Err() != nil {
			return resolved{reason: "timeout"}
		}
		return result
	case <-ctx.Done():
		inst.logger.Error("resolve timeout", "error", ctx.Err())
		return resolved{reason: "timeout"}
	}
}

func (h *Host) SearchInventory(ctx context.Context, q Query, sources []string) ([]Result, []SourceError) {
	type pending struct {
		inst instance
		done chan resolved
	}
	var calls []pending
	for _, inst := range h.instances {
		if !inst.ok || len(sources) > 0 && !slices.Contains(sources, inst.id) {
			continue
		}
		done := make(chan resolved, 1)
		calls = append(calls, pending{inst, done})
		go func() { done <- h.resolve(ctx, inst, inventory.Query{Kind: q.Kind}) }()
	}
	results := []Result{}
	errors := []SourceError{}
	for _, call := range calls {
		result := <-call.done
		if result.reason != "" {
			errors = append(errors, SourceError{Source: call.inst.id, Reason: result.reason})
			continue
		}
		discarded := 0
		for _, e := range result.entities {
			if !validEntity(e) {
				discarded++
				continue
			}
			if q.Kind != "" && e.Kind != q.Kind {
				continue
			}
			// Filter on the redacted name, so a name filter cannot probe a
			// redacted secret one character at a time.
			e.Name = h.redactor.Line(e.Name)
			if !strings.Contains(strings.ToLower(e.Name), strings.ToLower(q.Name)) {
				continue
			}
			for k, v := range e.Attrs {
				if h.redactor.Line(k) != k {
					delete(e.Attrs, k)
					continue
				}
				// "password=x" is recognised only with its key; "-px" only
				// as a standalone value. Redact both forms.
				prefix := k + "="
				value := h.redactor.Line(prefix + v)
				if strings.HasPrefix(value, prefix) {
					e.Attrs[k] = h.redactor.Line(strings.TrimPrefix(value, prefix))
				} else {
					e.Attrs[k] = "[REDACTED]"
				}
			}
			// A redacted selector would select other hosts; keep only Hosts.
			if h.redacts(e.Selector) {
				e.Selector = ""
			}
			for i, v := range e.DependsOn {
				if kind, name, ok := strings.Cut(v, "/"); ok {
					v = kind + "/" + h.redactor.Line(name)
				}
				e.DependsOn[i] = h.redactor.Line(v)
			}
			results = append(results, Result{Entity: e, Source: call.inst.id})
		}
		if discarded > 0 {
			call.inst.logger.Warn("invalid inventory entities discarded", "count", discarded)
		}
	}
	slices.SortFunc(results, func(a, b Result) int {
		if n := strings.Compare(a.Kind, b.Kind); n != 0 {
			return n
		}
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return strings.Compare(a.Source, b.Source)
	})
	return results, errors
}

// redacts reports whether redaction changes the selector or any of its
// keys and values on their own.
func (h *Host) redacts(selector string) bool {
	if h.redactor.Line(selector) != selector {
		return true
	}
	for _, term := range strings.Split(selector, ",") {
		key, value, _ := strings.Cut(term, "=")
		for _, part := range []string{term, key, value, strings.TrimSpace(key), strings.TrimSpace(value)} {
			if h.redactor.Line(part) != part {
				return true
			}
		}
	}
	return false
}

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
