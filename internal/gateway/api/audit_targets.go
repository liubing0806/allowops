package api

import (
	"context"
	"encoding/json"
	"strconv"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/audit"
)

// auditTarget contains only a resource type and its persisted identifier.
// It is populated from explicit successful responses or resolved database rows.
type auditTarget struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// resultTarget is an explicit whitelist. Never serialize a response or reflect
// over request fields: tokens, descriptions, parameters and bodies are excluded.
func resultTarget(ctx context.Context, req connect.AnyRequest, res connect.AnyResponse) {
	var kind, id string
	switch m := res.Any().(type) {
	case *v1.CreateServiceAccountResponse:
		kind, id = "service_account", m.GetAccount().GetAccountId()
	case *v1.UpdateServiceAccountResponse:
		kind, id = "service_account", m.GetAccount().GetAccountId()
	case *v1.CreateServiceAccountTokenResponse:
		kind, id = "service_account_token", m.GetToken().GetTokenId()
	case *v1.RevokeServiceAccountTokenResponse:
		kind, id = "service_account_token", req.Any().(*v1.RevokeServiceAccountTokenRequest).TokenId
	case *v1.SetUserRolesResponse:
		kind, id = "user", m.GetUser().GetUserId()
	case *v1.SaveRoleMappingsResponse:
		kind, id = "role_mappings", m.Revision
	case *v1.CreateJoinTokenResponse:
		kind, id = "join_token", m.GetToken().GetTokenId()
	case *v1.RevokeJoinTokenResponse:
		kind, id = "join_token", req.Any().(*v1.RevokeJoinTokenRequest).TokenId
	case *v1.RevokeCliSessionResponse:
		kind, id = "cli_session", req.Any().(*v1.RevokeCliSessionRequest).SessionId
	case *v1.TestPolicyResponse:
		kind, id = "policy_test", m.GetTest().GetTestId()
	case *v1.SavePolicyResponse:
		kind, id = "policy_version", strconv.FormatUint(m.GetPolicy().GetVersion(), 10)
	case *v1.RollbackPolicyResponse:
		kind, id = "policy_version", strconv.FormatUint(m.GetPolicy().GetVersion(), 10)
	case *v1.BeginCatalogUploadResponse:
		kind, id = "catalog_upload", m.UploadId
	case *v1.UploadCatalogChunkResponse:
		kind, id = "catalog_upload", req.Any().(*v1.UploadCatalogChunkRequest).UploadId
	case *v1.PublishCatalogResponse:
		ref := m.GetCatalog().GetCatalog()
		kind, id = "catalog_version", ref.GetCatalogId()+"@"+strconv.FormatUint(ref.GetVersion(), 10)
	case *v1.PreviewHostImportResponse:
		kind, id = "host_import_preview", m.GetPreview().GetPreviewId()
	}
	if id != "" {
		recordAuditTarget(ctx, kind, id)
	}
}

// Call after the database confirms a mutation, before fallible response reads.
// The result may still be an RPC failure; its persisted target must survive it.
func recordAuditTarget(ctx context.Context, kind, id string) {
	if t := transport(ctx); t != nil {
		t.auditTargets = []auditTarget{{Type: kind, ID: id}}
	}
}

func hostAuditTargets(ctx context.Context, hosts []*v1.Host) {
	t := transport(ctx)
	if t == nil {
		return
	}
	t.auditTargets = make([]auditTarget, len(hosts))
	for i, h := range hosts {
		t.auditTargets[i] = auditTarget{Type: "host", ID: h.HostId}
	}
	if len(hosts) == 1 {
		t.auditHostname = hosts[0].Hostname
	}
}

func targetResource(target auditTarget) string {
	raw, _ := json.Marshal(target)
	return string(raw)
}

// batchResource stays within the existing P7 Resource field. Each part carries
// a durable batch identifier and completeness metadata, independent of previews.
type batchResource struct {
	BatchID string        `json:"batch_id"`
	Part    int           `json:"part"`
	Parts   int           `json:"parts"`
	Total   int           `json:"total"`
	Targets []auditTarget `json:"targets"`
}

func resultResources(targets []auditTarget) ([]string, error) {
	const limit = 8 << 10 // Leaves room for JSON escaping and P7's other metadata.
	if len(targets) == 1 {
		resource := targetResource(targets[0])
		if len(resource) > limit {
			return nil, audit.ErrLimit
		}
		return []string{resource}, nil
	}
	batch := secret("audit_")
	groups := [][]auditTarget{}
	start, size := 0, 256 // Bounded header, including part counters and batch ID.
	for i, target := range targets {
		n := len(targetResource(target)) + 1
		if n+256 > limit {
			return nil, audit.ErrLimit
		}
		if size+n > limit {
			groups = append(groups, targets[start:i])
			start, size = i, 256
		}
		size += n
	}
	groups = append(groups, targets[start:])
	resources := make([]string, len(groups))
	for i, group := range groups {
		raw, _ := json.Marshal(batchResource{BatchID: batch, Part: i + 1, Parts: len(groups), Total: len(targets), Targets: group})
		if len(raw) > limit {
			return nil, audit.ErrLimit
		}
		resources[i] = string(raw)
	}
	return resources, nil
}
