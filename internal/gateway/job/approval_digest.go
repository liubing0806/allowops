package job

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
)

type frozenFilters struct {
	Match   *string `json:"match,omitempty"`
	Exclude *string `json:"exclude,omitempty"`
	Tail    *uint32 `json:"tail,omitempty"`
	Head    *uint32 `json:"head,omitempty"`
	Count   *bool   `json:"count,omitempty"`
}

type canonicalApprovalRequest struct {
	Version        int             `json:"v"`
	Action         string          `json:"action"`
	ActionRisk     string          `json:"action_risk"`
	CatalogID      string          `json:"catalog_id"`
	CatalogVersion int64           `json:"catalog_version"`
	ActionSHA256   string          `json:"action_sha256"`
	Params         json.RawMessage `json:"params"`
	Filters        json.RawMessage `json:"filters"`
	TargetHostIDs  []string        `json:"target_host_ids"`
	BatchSize      uint32          `json:"batch_size"`
	MaxFailures    uint32          `json:"max_failures"`
}

func freezeApproval(r *v1.RunJobRequest, p *catalog.Package, a catalog.Action, actionHash []byte, params map[string]any, targets []host, batch, failures uint32) (canonicalApprovalRequest, error) {
	// The gateway parser returns a typed duration. The host's parameter
	// decoder expects a Go duration string, just as for direct RunJob.
	for key, value := range params {
		if duration, ok := value.(time.Duration); ok {
			params[key] = duration.String()
		}
	}
	paramsJSON, err := catalog.CanonicalJSON(params)
	if err != nil {
		return canonicalApprovalRequest{}, err
	}
	if len(paramsJSON) > execd.MaxParameterBytes {
		return canonicalApprovalRequest{}, failure(connect.CodeInvalidArgument, "INVALID_PARAMETERS")
	}
	f := r.Filters
	filters := frozenFilters{}
	if f != nil {
		filters = frozenFilters{Match: f.Match, Exclude: f.Exclude, Tail: f.Tail, Head: f.Head, Count: f.Count}
	}
	filtersJSON, err := catalog.CanonicalJSON(filters)
	if err != nil {
		return canonicalApprovalRequest{}, err
	}
	ids := make([]string, len(targets))
	for i, target := range targets {
		ids[i] = target.ID
	}
	return canonicalApprovalRequest{
		Version: 1, Action: a.Name, ActionRisk: a.Risk, CatalogID: p.CatalogID, CatalogVersion: p.Version,
		ActionSHA256: hex.EncodeToString(actionHash), Params: paramsJSON, Filters: filtersJSON,
		TargetHostIDs: ids, BatchSize: batch, MaxFailures: failures,
	}, nil
}

func (p canonicalApprovalRequest) digest() ([sha256.Size]byte, error) {
	raw, err := catalog.CanonicalJSON(p)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

func (p canonicalApprovalRequest) request() (*v1.RunJobRequest, error) {
	var filters frozenFilters
	if err := execd.DecodeJSON(p.Filters, &filters); err != nil {
		return nil, err
	}
	r := &v1.RunJobRequest{Action: p.Action, Params: &v1.Parameters{Json: p.Params}}
	if !bytes.Equal(p.Filters, []byte("{}")) {
		r.Filters = &v1.OutputFilters{Match: filters.Match, Exclude: filters.Exclude, Tail: filters.Tail, Head: filters.Head, Count: filters.Count}
	}
	return r, nil
}
