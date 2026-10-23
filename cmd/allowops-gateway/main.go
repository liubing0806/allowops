package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/gateway/api"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/catalogsvc"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/mcp"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"github.com/liubing0806/allowops/internal/gateway/server"
	"github.com/liubing0806/allowops/internal/store"
	"gopkg.in/yaml.v3"
)

var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type configuration struct {
	Address        string          `yaml:"address"`
	TLSCertificate string          `yaml:"tls_certificate"`
	TLSKey         string          `yaml:"tls_key"`
	CACertificate  string          `yaml:"ca_certificate"`
	CAKey          string          `yaml:"ca_key"`
	CatalogKeys    string          `yaml:"catalog_keys"`
	Gateway        hostconn.Config `yaml:"gateway"`
	Audit          struct {
		Export struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"export"`
		ExportDirectory string `yaml:"export_directory"`
		CursorName      string `yaml:"cursor_name"`
		MaxFileBytes    int64  `yaml:"max_file_bytes"`
		CursorKeyFile   string `yaml:"cursor_key_file"`
	} `yaml:"audit"`
	Management api.ManagementConfig `yaml:"management"`
	Identity   api.Config           `yaml:"identity"`
	Providers  []api.ProviderConfig `yaml:"providers"`
	Jobs       job.Config           `yaml:"jobs"`
	Output     output.Config        `yaml:"output"`
}

func run(args []string) error {
	return runWithAudit(args, nil)
}

// Tests may inject an auditor; production uses the audit module's PostgreSQL Appender (design P7).
func runWithAudit(args []string, auditor api.Auditor) error {
	if len(args) > 0 && args[0] == "health" {
		return runHealth(args[1:])
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: allowops-gateway migrate | serve --config <file>")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	dsn := os.Getenv("ALLOWOPS_DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("ALLOWOPS_DATABASE_URL required")
	}
	switch args[0] {
	case "migrate":
		if len(args) != 1 {
			return fmt.Errorf("migrate accepts no arguments")
		}
		if err := store.Migrate(ctx, dsn); err != nil {
			return err
		}
		fmt.Printf("schema migrated to %d\n", store.SchemaVersion)
		return nil
	case "serve":
		return serve(ctx, dsn, args[1:], auditor)
	default:
		return fmt.Errorf("unknown gateway command")
	}
}

// serve starts the gateway and blocks until shutdown. Deferred cleanups run in
// reverse order of acquisition: audit workers, jobs, identity, database, config file.
func serve(ctx context.Context, dsn string, args []string, auditor api.Auditor) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := flags.String("config", "", "Gateway YAML configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return fmt.Errorf("serve --config <file> required")
	}
	f, err := os.Open(*path)
	if err != nil {
		return fmt.Errorf("open gateway config")
	}
	defer f.Close()
	cfg, err := decodeConfiguration(f)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.CheckSchema(ctx); err != nil {
		return err
	}
	auditCfg, err := cfg.auditConfig(os.Stderr)
	if err != nil {
		return err
	}
	auditStore := audit.New(db.Pool, auditCfg)
	if auditor == nil {
		auditor = api.NewAuditor(auditStore)
	}
	identity, err := startIdentity(ctx, db, cfg, auditor)
	if err != nil {
		return err
	}
	defer identity.Close()
	ca, certificate, trusted, err := loadTrustMaterial(cfg)
	if err != nil {
		return err
	}
	agent, objects, jobs, err := newJobServices(ctx, db, identity, ca, cfg, auditStore, trusted)
	if err != nil {
		return err
	}
	defer jobs.Close()
	listener, err := startJobServices(identity, agent, objects, jobs, cfg.Address)
	if err != nil {
		return err
	}
	srv, err := newGatewayServer(&cfg, db, identity, agent, listener, certificate, trusted, auditStore, objects, jobs)
	if err != nil {
		return err
	}
	auditErrors, stopAudit := startAuditWorkers(&cfg, auditStore)
	defer stopAudit()
	return serveUntilDone(ctx, cfg, srv, agent, listener, auditErrors, stopAudit)
}

// decodeConfiguration applies defaults, then the YAML file, and rejects unknown fields.
func decodeConfiguration(f *os.File) (configuration, error) {
	cfg := configuration{Address: ":443", Gateway: hostconn.DefaultConfig(), Identity: api.Config{Origin: "https://localhost"}, Jobs: job.DefaultConfig()}
	if version != "dev" {
		cfg.Gateway.Version = version
	}
	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid gateway config: %w", err)
	}
	if cfg.Audit.Export.Enabled && (cfg.Audit.ExportDirectory == "" || cfg.Audit.CursorName == "") {
		return cfg, fmt.Errorf("audit export_directory and cursor_name required when audit.export.enabled=true")
	}
	return cfg, nil
}

// startIdentity builds the identity service and starts it. The caller closes it.
func startIdentity(ctx context.Context, db *store.Store, cfg configuration, auditor api.Auditor) (*api.Service, error) {
	identity, err := api.New(ctx, db, cfg.Identity, auditor)
	if err != nil {
		return nil, err
	}
	if err := identity.ConfigureProviders(ctx, cfg.Providers); err != nil {
		return nil, err
	}
	if err := identity.Start(ctx); err != nil {
		return nil, err
	}
	return identity, nil
}

func loadTrustMaterial(cfg configuration) (*hostconn.CA, tls.Certificate, map[string]ed25519.PublicKey, error) {
	ca, err := hostconn.OpenCA(cfg.CACertificate, cfg.CAKey)
	if err != nil {
		return nil, tls.Certificate{}, nil, fmt.Errorf("load host CA: %w", err)
	}
	certificate, err := tls.LoadX509KeyPair(cfg.TLSCertificate, cfg.TLSKey)
	if err != nil {
		return nil, tls.Certificate{}, nil, fmt.Errorf("load gateway TLS certificate")
	}
	trusted, err := loadCatalogKeys(cfg.CatalogKeys)
	if err != nil {
		return nil, tls.Certificate{}, nil, err
	}
	return ca, certificate, trusted, nil
}

// newJobServices constructs the host connection service, object storage and
// job service without starting any of them. The caller closes jobs.
func newJobServices(ctx context.Context, db *store.Store, identity *api.Service, ca *hostconn.CA, cfg configuration, auditStore *audit.Store, trusted map[string]ed25519.PublicKey) (*hostconn.Service, *output.S3, *job.Service, error) {
	agent, err := hostconn.New(db, ca, cfg.Gateway, hostconn.Hooks{})
	if err != nil {
		return nil, nil, nil, err
	}
	objects, err := output.New(ctx, cfg.Output)
	if err != nil {
		return nil, nil, nil, err
	}
	jobs, err := job.New(db, identity, agent, objects, auditStore, trusted, cfg.Jobs)
	if err != nil {
		return nil, nil, nil, err
	}
	return agent, objects, jobs, nil
}

// startJobServices wires the job hooks, starts the host connection and job
// services, and opens the listener. If the listen fails, it closes the agent.
func startJobServices(identity *api.Service, agent *hostconn.Service, objects *output.S3, jobs *job.Service, address string) (net.Listener, error) {
	identity.ConfigureJobDependencies(jobs, objects)
	agent.Hooks = jobs.Hooks()
	// Shutdown owns cancellation after Reconnect has been sent.
	if err := agent.Start(context.Background()); err != nil {
		return nil, err
	}
	jobs.Start()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		agent.Close()
		return nil, fmt.Errorf("listen gateway")
	}
	return listener, nil
}

// newGatewayServer configures management and MCP and assembles the server.
// On failure it closes the agent and the listener.
func newGatewayServer(cfg *configuration, db *store.Store, identity *api.Service, agent *hostconn.Service, listener net.Listener, certificate tls.Certificate, trusted map[string]ed25519.PublicKey, auditStore *audit.Store, objects *output.S3, jobs *job.Service) (*server.Server, error) {
	catalogs := &catalogsvc.Service{Store: db, Trusted: trusted, MaxEnvelopeBytes: cfg.Gateway.EnvelopeBytes, MaxActionBytes: cfg.Gateway.ActionBytes, MaxReferenceBytes: cfg.Gateway.MessageBytes - cfg.Gateway.ChunkBytes - 1024}
	if cfg.Management.CAPin == "" {
		cfg.Management.CAPin = api.TLSCAPin(certificate.Certificate)
	}
	if cfg.Management.CAPin == "" {
		fmt.Fprintln(os.Stderr, "gateway TLS CA pin unavailable; CreateJoinToken disabled; configure management.ca_pin")
	}
	if err := identity.ConfigureManagement(cfg.Management, agent, catalogs); err != nil {
		agent.Close()
		listener.Close()
		return nil, err
	}
	mcpService, err := mcp.New(identity, catalogs, job.Client(jobs), mcp.Config{})
	if err != nil {
		agent.Close()
		listener.Close()
		return nil, err
	}
	srv := server.New(agent, certificate,
		server.WithIdentity(identity),
		server.WithAudit(&audit.Service{Store: auditStore}),
		server.WithMCP(mcpService.Handler()),
	)
	srv.Output = objects
	srv.Jobs = jobs
	srv.Catalogs = catalogs
	return srv, nil
}

// startAuditWorkers runs the checkpoint worker and, when enabled, the exporter.
// A worker that stops sends on the returned channel.
func startAuditWorkers(cfg *configuration, auditStore *audit.Store) (<-chan error, context.CancelFunc) {
	auditCtx, stopAudit := context.WithCancel(context.Background())
	auditErrors := make(chan error, 2)
	go func() { auditErrors <- auditStore.RunCheckpoints(auditCtx) }()
	if cfg.Audit.Export.Enabled {
		if cfg.Audit.MaxFileBytes == 0 {
			cfg.Audit.MaxFileBytes = 16 << 20
		}
		exporter := &audit.Exporter{Store: auditStore, Cursor: cfg.Audit.CursorName, Storage: audit.FileStorage{Directory: cfg.Audit.ExportDirectory, MaxBytes: cfg.Audit.MaxFileBytes}}
		go func() { auditErrors <- exporter.Run(auditCtx, time.Second) }()
	}
	return auditErrors, stopAudit
}

// serveUntilDone serves until a signal, an audit worker failure or a listener
// failure, then shuts the server down.
func serveUntilDone(ctx context.Context, cfg configuration, srv *server.Server, agent *hostconn.Service, listener net.Listener, auditErrors <-chan error, stopAudit context.CancelFunc) error {
	finished := make(chan error, 1)
	go func() { finished <- srv.Serve(listener) }()
	fmt.Printf("gateway serving %s schema=%d\n", listener.Addr(), store.SchemaVersion)
	select {
	case <-ctx.Done():
	case <-auditErrors:
		stopAudit()
		agent.Close()
		listener.Close()
		return fmt.Errorf("audit background worker stopped")
	case err := <-finished:
		if err != nil {
			agent.Close()
			return fmt.Errorf("gateway listener failed")
		}
	}
	stopAudit()
	shutdown, done := context.WithTimeout(context.Background(), cfg.Gateway.ShutdownGrace+5*time.Second)
	defer done()
	if err := srv.Shutdown(shutdown); err != nil {
		return fmt.Errorf("gateway shutdown: %w", err)
	}
	fmt.Println("gateway stopped")
	return nil
}

func loadCatalogKeys(path string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	if path == "" {
		return keys, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog trust anchors")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read catalog public key")
		}
		key, err := catalog.ParsePublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("invalid catalog public key")
		}
		keys[catalog.KeyID(key)] = key
	}
	return keys, nil
}
