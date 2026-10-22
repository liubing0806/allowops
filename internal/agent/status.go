package agent

import (
	"encoding/json"
	"os"
	"syscall"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/execd"
)

type ServiceStatus struct {
	HostID         string           `json:"host_id"`
	Hostname       string           `json:"hostname"`
	Upstream       string           `json:"upstream"`
	ExpiresAt      time.Time        `json:"expires_at"`
	Running        bool             `json:"running"`
	Connected      bool             `json:"connected"`
	PID            int              `json:"pid"`
	ConnectionID   string           `json:"connection_id,omitempty"`
	LoadedCatalogs []*v1.CatalogRef `json:"loaded_catalogs,omitempty"`
}

func Status(dataDir string) (ServiceStatus, error) {
	identity, err := LoadIdentity(dataDir)
	if err != nil {
		return ServiceStatus{}, err
	}
	result := ServiceStatus{HostID: identity.HostID, Hostname: identity.Hostname, Upstream: identity.Upstream, ExpiresAt: identity.ExpiresAt}
	owner, _, err := identityOwner()
	if err != nil {
		return result, err
	}
	dir, err := execd.OpenDirectory(dataDir, false, owner, true)
	if err != nil {
		return result, err
	}
	defer dir.Close()
	data, err := execd.ReadPrivateFile(dir, "status.json", MaxMessageBytes, owner)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if err := execd.DecodeJSON(data, &result); err != nil {
		return result, err
	}
	result.ExpiresAt = identity.ExpiresAt
	if result.PID <= 0 || syscall.Kill(result.PID, 0) != nil {
		result.Running = false
		result.Connected = false
	}
	return result, nil
}

func (a *Agent) writeStatus(connectionID string, running bool) error {
	identity := a.identity.get()
	status := ServiceStatus{HostID: identity.HostID, Hostname: identity.Hostname, Upstream: identity.Upstream, ExpiresAt: identity.ExpiresAt, Running: running, Connected: connectionID != "", PID: os.Getpid(), ConnectionID: connectionID, LoadedCatalogs: a.catalogs.refs()}
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	dir, err := execd.OpenDirectory(a.options.DataDir, false, os.Getuid(), true)
	if err != nil {
		return err
	}
	defer dir.Close()
	return execd.AtomicWrite(dir, "status.json", data)
}
