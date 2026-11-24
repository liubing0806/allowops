// Package plugin defines the experimental gateway plugin API.
package plugin

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"
)

type ModuleID string

type ModuleInfo struct {
	ID  ModuleID
	New func() Module
}

type Module interface{ Module() ModuleInfo }

type Provisioner interface {
	Provision(ctx context.Context, h Host) error
}

// Validator checks module configuration without performing I/O.
type Validator interface {
	Validate() error
}

type Cleaner interface {
	Cleanup(ctx context.Context) error
}

// Cache stores instance-local values. Get and Set copy values. A nonpositive
// TTL deletes the entry.
type Cache interface {
	Get(key string) ([]byte, bool)
	Set(key string, value []byte, ttl time.Duration)
	Delete(key string)
}

type ControlPlaneChange struct {
	At             time.Time
	Kind           string // "catalog" or "policy"
	CatalogID      string
	Version        int64
	ActionCount    int
	Actor          string
	Reason         string
	RolledBackFrom int64
}

// ControlPlaneChangeReader is an optional capability of the changes.allowops host.
type ControlPlaneChangeReader interface {
	ListControlPlaneChanges(ctx context.Context, from, to time.Time, limit int) (items []ControlPlaneChange, hasMore bool, err error)
}

// Host exposes gateway capabilities to plugins. Hosts returns all active hosts;
// caller visibility is applied by the gateway after resolving inventory.
type Host interface {
	InstanceID() string
	Logger() *slog.Logger
	Hosts(ctx context.Context) ([]HostInfo, error)
	// HTTPClient permits only requests allowed by the instance's egress policy.
	HTTPClient() *http.Client
	Credential(ref string) ([]byte, error)
	Cache() Cache
	// Now returns the current UTC time.
	Now() time.Time
}

type HostInfo struct {
	Hostname       string
	Labels         map[string]string
	ReportedLabels map[string]string
}

var (
	moduleID   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$`)
	registryMu sync.RWMutex
	registry   = map[ModuleID]ModuleInfo{}
)

// Register registers a compiled module. Invalid or duplicate IDs panic.
func Register(m Module) {
	info := m.Module()
	if !moduleID.MatchString(string(info.ID)) {
		panic("invalid plugin module ID: " + string(info.ID))
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[info.ID]; exists {
		panic("duplicate plugin module ID: " + string(info.ID))
	}
	registry[info.ID] = info
}

func Lookup(id ModuleID) (ModuleInfo, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	info, ok := registry[id]
	return info, ok
}
