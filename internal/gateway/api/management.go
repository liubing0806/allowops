package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
)

type ManagementConfig struct {
	PreviewTTL        time.Duration `yaml:"preview_ttl"`
	UploadTTL         time.Duration `yaml:"upload_ttl"`
	MaxCSVBytes       int           `yaml:"max_csv_bytes"`
	MaxCSVRows        int           `yaml:"max_csv_rows"`
	LabelCount        int           `yaml:"label_count"`
	LabelKeyBytes     int           `yaml:"label_key_bytes"`
	LabelValueBytes   int           `yaml:"label_value_bytes"`
	LabelCountBuckets int           `yaml:"label_count_buckets"`
	Upstream          string        `yaml:"upstream"`
	CAPin             string        `yaml:"ca_pin"`
}

type management struct {
	config   ManagementConfig
	agent    *hostconn.Service
	catalogs *catalogsvc.Service
}

func defaultManagement() *management {
	return &management{config: ManagementConfig{PreviewTTL: 10 * time.Minute, UploadTTL: time.Hour, MaxCSVBytes: 512 << 10, MaxCSVRows: 5000, LabelCount: 128, LabelKeyBytes: 128, LabelValueBytes: 1024, LabelCountBuckets: 200}}
}

func (s *Service) ConfigureManagement(cfg ManagementConfig, agent *hostconn.Service, catalogs *catalogsvc.Service) error {
	d := defaultManagement().config
	if cfg.PreviewTTL == 0 {
		cfg.PreviewTTL = d.PreviewTTL
	}
	if cfg.UploadTTL == 0 {
		cfg.UploadTTL = d.UploadTTL
	}
	if cfg.MaxCSVBytes == 0 {
		cfg.MaxCSVBytes = d.MaxCSVBytes
	}
	if cfg.MaxCSVRows == 0 {
		cfg.MaxCSVRows = d.MaxCSVRows
	}
	if cfg.LabelCount == 0 {
		cfg.LabelCount = d.LabelCount
	}
	if cfg.LabelKeyBytes == 0 {
		cfg.LabelKeyBytes = d.LabelKeyBytes
	}
	if cfg.LabelValueBytes == 0 {
		cfg.LabelValueBytes = d.LabelValueBytes
	}
	if cfg.LabelCountBuckets == 0 {
		cfg.LabelCountBuckets = d.LabelCountBuckets
	}
	if cfg.PreviewTTL <= 0 || cfg.UploadTTL <= 0 || cfg.MaxCSVBytes < 1 || cfg.MaxCSVBytes > d.MaxCSVBytes || cfg.MaxCSVRows < 1 || cfg.MaxCSVRows > d.MaxCSVRows || cfg.LabelCount < 1 || cfg.LabelCount > d.LabelCount || cfg.LabelKeyBytes < 1 || cfg.LabelKeyBytes > d.LabelKeyBytes || cfg.LabelValueBytes < 1 || cfg.LabelValueBytes > d.LabelValueBytes || cfg.LabelCountBuckets < 1 || cfg.LabelCountBuckets > d.LabelCountBuckets {
		return errors.New("invalid management limits")
	}
	if cfg.CAPin != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(cfg.CAPin, "sha256:"))
		if !strings.HasPrefix(cfg.CAPin, "sha256:") || err != nil || len(b) != sha256.Size {
			return errors.New("management.ca_pin must be sha256 of TLS CA DER")
		}
	}
	s.management = &management{cfg, agent, catalogs}
	return nil
}

func (s *Service) gatewayConfig() hostconn.Config {
	if s.management.agent != nil {
		return s.management.agent.Config
	}
	return hostconn.DefaultConfig()
}

func (s *Service) mountManagement(mux *http.ServeMux) {
	p := map[string]RPCPermission{}
	for _, proc := range []string{rpc.HostServiceListHostsProcedure, rpc.HostServiceGetHostProcedure} {
		p[proc] = RPCPermission{Operation: authz.ViewHosts, Resource: true}
	}
	for _, proc := range []string{rpc.HostServiceSetHostLabelsProcedure, rpc.HostServicePreviewHostImportProcedure, rpc.HostServiceExecuteHostImportProcedure, rpc.HostServiceDeleteHostProcedure} {
		p[proc] = RPCPermission{Operation: authz.ManageHosts, Write: true, Resource: true}
	}
	p[rpc.HostServiceGetHostImportPreviewProcedure] = RPCPermission{Operation: authz.ManageHosts, Resource: true}
	for _, proc := range []string{rpc.JoinTokenServiceCreateJoinTokenProcedure, rpc.JoinTokenServiceRevokeJoinTokenProcedure} {
		p[proc] = RPCPermission{Operation: authz.CreateJoinToken, Write: true}
	}
	p[rpc.JoinTokenServiceListJoinTokensProcedure] = RPCPermission{Operation: authz.CreateJoinToken}
	for _, proc := range []string{rpc.CatalogServiceBeginCatalogUploadProcedure, rpc.CatalogServiceUploadCatalogChunkProcedure, rpc.CatalogServicePublishCatalogProcedure} {
		p[proc] = RPCPermission{Operation: authz.PublishCatalog, Write: true}
	}
	for _, proc := range []string{rpc.CatalogServiceListCatalogsProcedure, rpc.CatalogServiceGetCatalogProcedure} {
		p[proc] = RPCPermission{Operation: authz.ViewCatalog}
	}
	for _, proc := range []string{rpc.CatalogServiceListActionsProcedure, rpc.CatalogServiceGetActionProcedure, rpc.CatalogServiceGetCatalogDistributionProcedure} {
		p[proc] = RPCPermission{Operation: authz.ViewCatalog, Resource: true}
	}
	for _, proc := range []string{rpc.SystemServiceGetSystemStatusProcedure, rpc.SystemServiceListGatewayInstancesProcedure, rpc.SystemServiceGetAgentVersionDistributionProcedure} {
		p[proc] = RPCPermission{Operation: authz.ViewSystem}
	}
	opts := []connect.HandlerOption{connect.WithInterceptors(s.InterceptorFor(p)), connect.WithReadMaxBytes(s.Config.MessageBytes), connect.WithSendMaxBytes(s.Config.MessageBytes)}
	mux.Handle(rpc.NewHostServiceHandler(s, opts...))
	mux.Handle(rpc.NewJoinTokenServiceHandler(s, opts...))
	mux.Handle(rpc.NewCatalogServiceHandler(s, opts...))
	mux.Handle(rpc.NewSystemServiceHandler(s, opts...))
}

// authorizeWrite is called after every target's authorization and revision check,
// with target row locks held, and before the first mutation; writes are audited in two phases, authorized then result (design G28).
func (s *Service) authorizeWrite(ctx context.Context) error {
	t := transport(ctx)
	if t == nil || !t.resource {
		return failure(connect.CodeUnauthenticated, "authentication required")
	}
	if err := s.Audit.Append(ctx, AuditEvent{ActorID: reqctx.ActorID(ctx), Operation: t.procedure, Phase: "authorized", Outcome: "allow", PolicyVersion: t.policyVersion, MatchedRules: t.matchedRules, SourceIP: t.ip}); err != nil {
		t.authorizationAuditFailed = true
		return failure(connect.CodeUnavailable, "authorization audit unavailable; operation not executed")
	}
	t.writeAuthorized = true
	return nil
}

func (s *Service) can(ctx context.Context, op authz.Operation, action authz.Action, host authz.Host) (bool, error) {
	previous := slices.Clone(transport(ctx).matchedRules)
	_, err := s.Require(ctx, op, action, host)
	transport(ctx).matchedRules = unique(append(previous, transport(ctx).matchedRules...))
	if err == nil {
		return true, nil
	}
	if connect.CodeOf(err) == connect.CodePermissionDenied {
		return false, nil
	}
	return false, err
}

// TLSCAPin only derives a pin from a self-signed CA in the gateway TLS chain.
func TLSCAPin(chain [][]byte) string {
	for _, raw := range chain {
		c, err := x509.ParseCertificate(raw)
		if err == nil && c.IsCA && bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
			sum := sha256.Sum256(c.Raw)
			return "sha256:" + hex.EncodeToString(sum[:])
		}
	}
	return ""
}
