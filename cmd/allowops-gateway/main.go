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

// auditPoolConns bounds the audit store's own pool: three connections for the
// export leader, its batch and the batch's page read, and three for appends and
// audit queries.
const auditPoolConns = 6

func run(args []string) error {
	return runWithAudit(args, nil)
}

// Tests may inject an auditor; production uses P7's PostgreSQL Appender.
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
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		path := flags.String("config", "", "Gateway YAML configuration")
		if err := flags.Parse(args[1:]); err != nil {
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
		cfg := configuration{Address: ":443", Gateway: hostconn.DefaultConfig(), Identity: api.Config{Origin: "https://localhost"}, Jobs: job.DefaultConfig()}
		if version != "dev" {
			cfg.Gateway.Version = version
		}
		decoder := yaml.NewDecoder(f)
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			return fmt.Errorf("invalid gateway config: %w", err)
		}
		if cfg.Audit.Export.Enabled && (cfg.Audit.ExportDirectory == "" || cfg.Audit.CursorName == "") {
			return fmt.Errorf("audit export_directory and cursor_name required when audit.export.enabled=true")
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
		// Host write handlers append audit events while holding a business
		// transaction connection, so the audit store never shares db's pool. The
		// pool stays small: appends serialize on one advisory lock, so extra
		// connections only queue (see auditPoolConns).
		auditPool, err := store.OpenPool(ctx, dsn, auditPoolConns)
		if err != nil {
			return err
		}
		defer auditPool.Close()
		auditStore := audit.New(auditPool, auditCfg)
		if auditor == nil {
			auditor = api.NewAuditor(auditStore)
		}
		cfg.Identity.Version = version
		identity, err := api.New(ctx, db, cfg.Identity, auditor)
		if err != nil {
			return err
		}
		if err := identity.ConfigureProviders(ctx, cfg.Providers); err != nil {
			return err
		}
		if err := identity.Start(ctx); err != nil {
			return err
		}
		defer identity.Close()
		ca, err := hostconn.OpenCA(cfg.CACertificate, cfg.CAKey)
		if err != nil {
			return fmt.Errorf("load host CA: %w", err)
		}
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertificate, cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("load gateway TLS certificate")
		}
		trusted, err := loadCatalogKeys(cfg.CatalogKeys)
		if err != nil {
			return err
		}
		agent, err := hostconn.New(db, ca, cfg.Gateway, hostconn.Hooks{})
		if err != nil {
			return err
		}
		objects, err := output.New(ctx, cfg.Output)
		if err != nil {
			return err
		}
		jobs, err := job.New(db, identity, agent, objects, auditStore, trusted, cfg.Jobs)
		if err != nil {
			return err
		}
		defer jobs.Close()
		identity.ConfigureJobDependencies(jobs, objects)
		agent.Hooks = jobs.Hooks()
		// Shutdown owns cancellation after Reconnect has been sent.
		if err := agent.Start(context.Background()); err != nil {
			return err
		}
		jobs.Start()
		listener, err := net.Listen("tcp", cfg.Address)
		if err != nil {
			agent.Close()
			return fmt.Errorf("listen gateway")
		}
		srv := server.New(agent, certificate)
		srv.Output = objects
		srv.Jobs = jobs
		srv.Audit = &audit.Service{Store: auditStore}
		srv.Catalogs = &catalogsvc.Service{Store: db, Trusted: trusted, MaxEnvelopeBytes: cfg.Gateway.EnvelopeBytes, MaxActionBytes: cfg.Gateway.ActionBytes, MaxReferenceBytes: cfg.Gateway.MessageBytes - cfg.Gateway.ChunkBytes - 1024}
		if cfg.Management.CAPin == "" {
			cfg.Management.CAPin = api.TLSCAPin(certificate.Certificate)
		}
		if cfg.Management.CAPin == "" {
			fmt.Fprintln(os.Stderr, "gateway TLS CA pin unavailable; CreateJoinToken disabled; configure management.ca_pin")
		}
		if err := identity.ConfigureManagement(cfg.Management, agent, srv.Catalogs); err != nil {
			agent.Close()
			listener.Close()
			return err
		}
		srv.UseIdentity(identity)
		mcpService, err := mcp.New(identity, srv.Catalogs, job.Client(jobs), mcp.Config{Jobs: cfg.Jobs})
		if err != nil {
			agent.Close()
			listener.Close()
			return err
		}
		srv.MCP = mcpService.Handler()
		auditCtx, stopAudit := context.WithCancel(context.Background())
		defer stopAudit()
		auditErrors := make(chan error, 2)
		go func() { auditErrors <- auditStore.RunCheckpoints(auditCtx) }()
		if cfg.Audit.Export.Enabled {
			if cfg.Audit.MaxFileBytes == 0 {
				cfg.Audit.MaxFileBytes = 16 << 20
			}
			exporter := &audit.Exporter{Store: auditStore, Cursor: cfg.Audit.CursorName, Storage: audit.FileStorage{Directory: cfg.Audit.ExportDirectory, MaxBytes: cfg.Audit.MaxFileBytes}}
			go func() { auditErrors <- exporter.Run(auditCtx, time.Second) }()
		}
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
	default:
		return fmt.Errorf("unknown gateway command")
	}
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
