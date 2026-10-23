package agent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/execd"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Options struct {
	Version  string
	DataDir  string
	KeysDir  string
	KeyOwner int
	Runner   Runner
	// Sleep is injectable so retry timing can be tested without waiting 30s.
	Sleep func(context.Context, time.Duration) error
}

type Agent struct {
	config   Config
	options  Options
	identity *identityStore
	catalogs *catalogs
}

func New(config Config, options Options) (*Agent, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	config.Limits = config.Limits.defaults()
	if options.DataDir == "" {
		options.DataDir = DataDirectory
	}
	if options.KeysDir == "" {
		options.KeysDir = execd.KeyDirectory
	}
	if options.Version == "" {
		options.Version = "dev"
	}
	if options.Runner == nil {
		options.Runner = LocalRunner{}
	}
	if options.Sleep == nil {
		options.Sleep = sleep
	}
	value, err := LoadIdentity(options.DataDir)
	if err != nil {
		return nil, err
	}
	upstream, _ := upstreamURL(config.Upstream)
	joinedUpstream, _ := upstreamURL(value.Upstream)
	if upstream != joinedUpstream || config.CAPin != value.CAPin {
		return nil, errors.New("IDENTITY_CONFIG_MISMATCH")
	}
	if !value.ExpiresAt.After(time.Now()) {
		return nil, errors.New("CERTIFICATE_EXPIRED")
	}
	if len(value.ClientCA) == 0 {
		return nil, errors.New("INVALID_IDENTITY")
	}
	if _, err := acceptCertificate(config, value.Hostname, value.PrivateKey, &v1.HostCertificate{HostId: value.HostID, CertificateChainPem: value.Certificate, ExpiresAt: timestamppb.New(value.ExpiresAt), RenewAfter: timestamppb.New(value.RenewAfter)}, value.HostID, value.ClientCA); err != nil {
		return nil, err
	}
	cache := execd.Cache{CatalogDir: filepath.Join(options.DataDir, "catalogs"), KeysDir: options.KeysDir, StateDir: filepath.Join(options.DataDir, "versions"), StateOwner: os.Getuid(), KeyOwner: options.KeyOwner, MaxBytes: config.Limits.CatalogBytes}
	catalogs := &catalogs{loaded: map[string]*catalog.Package{}, cache: cache, limits: config.Limits}
	catalogs.restore()
	return &Agent{config: config, options: options, identity: &identityStore{value: value}, catalogs: catalogs}, nil
}

func sleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *Agent) backoff(attempt uint) time.Duration {
	minimum, maximum := a.config.Limits.ReconnectMin, a.config.Limits.ReconnectMax
	upper := minimum
	for i := uint(0); i <= min(attempt, 63); i++ {
		if upper >= maximum/2 {
			upper = maximum
			break
		}
		upper *= 2
	}
	return minimum + time.Duration(rand.Int64N(int64(upper-minimum)+1))
}

func (a *Agent) hello() *v1.AgentHello {
	labels := map[string]string{"os": runtime.GOOS, "arch": runtime.GOARCH, "hostname": a.identity.get().Hostname}
	for key, value := range a.config.ReportedLabels {
		labels[key] = value
	}
	return &v1.AgentHello{AgentVersion: a.options.Version, Capabilities: &v1.AgentCapabilities{CatalogSchemaVersions: []uint32{1}, ParameterTypes: []string{"enum", "int", "string", "duration", "path", "url", "bool", "string_array"}, ExecutionModes: []string{"exec", "steps", "script", "builtin"}, Builtins: []string{"log_search", "log_query", "http_get", "redis_command", "mysql_query"}, OutputFilters: []string{"match", "exclude", "tail", "head", "count"}, Features: []string{"allow_interpreter", "exec_fallbacks"}}, ReportedLabels: labels, LoadedCatalogs: a.catalogs.refs(), MaxConcurrentTasks: uint32(a.config.Limits.ConcurrentTasks)}
}

func (a *Agent) Run(parent context.Context) error {
	dir, err := execd.OpenDirectory(a.options.DataDir, false, os.Getuid(), true)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("AGENT_ALREADY_RUNNING")
	}
	defer syscall.Flock(int(dir.Fd()), syscall.LOCK_UN)
	if err := a.writeStatus("", true); err != nil {
		return err
	}
	defer a.writeStatus("", false)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	client, transport, err := newClient(a.config, a.identity)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	renewDone := make(chan struct{})
	renewErr := make(chan error, 1)
	go func() {
		defer close(renewDone)
		var attempt uint
		for ctx.Err() == nil {
			value := a.identity.get()
			delay := max(time.Second, time.Until(value.RenewAfter))
			if attempt > 0 {
				delay = a.backoff(attempt - 1)
			}
			delay = min(delay, max(0, time.Until(value.ExpiresAt)))
			if err := a.options.Sleep(ctx, delay); err != nil {
				return
			}
			if !a.identity.get().ExpiresAt.After(time.Now()) {
				renewErr <- errors.New("CERTIFICATE_EXPIRED")
				cancel()
				return
			}
			rpcCtx, rpcCancel := context.WithTimeout(ctx, min(10*time.Second, time.Until(value.ExpiresAt)))
			renewClient, renewTransport, err := newClient(a.config, a.identity)
			if err == nil {
				err = renew(rpcCtx, renewClient, a.config, a.options.DataDir, a.identity)
				renewTransport.CloseIdleConnections()
			}
			rpcCancel()
			if err != nil {
				attempt++
				continue
			}
			attempt = 0
			transport.CloseIdleConnections()
		}
	}()
	defer func() { cancel(); <-renewDone }()
	var rejection string
	for attempt := uint(0); ctx.Err() == nil; attempt++ {
		started := time.Now()
		delay, err := a.session(ctx, client)
		transport.CloseIdleConnections()
		if ctx.Err() != nil {
			break
		}
		// Log a rejection once until the next different outcome; retries repeat it every few seconds.
		if message, ok := rejectedVersion(err); !ok {
			rejection = ""
		} else if message != rejection {
			rejection = message
			slog.Warn("gateway rejected agent version", "agent_version", a.options.Version, "reason", "AGENT_VERSION_UNSUPPORTED", "error", message)
		}
		if time.Since(started) >= 45*time.Second {
			attempt = 0
		}
		if delay == 0 {
			delay = a.backoff(attempt)
		}
		if err := a.options.Sleep(ctx, delay); err != nil {
			break
		}
	}
	select {
	case err := <-renewErr:
		return err
	default:
		return parent.Err()
	}
}

// rejectedVersion reports the gateway's message when it refused this agent version.
func rejectedVersion(err error) (string, bool) {
	var e *connect.Error
	if !errors.As(err, &e) || e.Code() != connect.CodeUnimplemented {
		return "", false
	}
	for _, d := range e.Details() {
		if v, err := d.Value(); err == nil {
			if detail, ok := v.(*v1.ErrorDetail); ok && detail.Reason == "AGENT_VERSION_UNSUPPORTED" {
				return e.Message(), true
			}
		}
	}
	return "", false
}
