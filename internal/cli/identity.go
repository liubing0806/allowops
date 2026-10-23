package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type credentials struct {
	Gateway   string    `json:"gateway"`
	CAFile    string    `json:"ca_file,omitempty"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func credentialPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "allowops", "credentials"), nil
}
func saveCredentials(c credentials) error {
	path, err := credentialPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".credentials-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	b, err := json.Marshal(c)
	if err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func loadCredentials() (credentials, error) {
	path, err := credentialPath()
	if err != nil {
		return credentials{}, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return credentials{}, errors.New("login required")
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return credentials{}, errors.New("credentials must be a regular file with permissions 0600")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return credentials{}, err
	}
	var c credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return c, errors.New("invalid credentials file")
	}
	if c.Token == "" || !time.Now().Before(c.ExpiresAt) {
		return c, errors.New("session expired; login required")
	}
	return c, nil
}
func gatewayClient(gateway, caFile string) (*http.Client, error) {
	u, err := url.Parse(gateway)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("gateway must be an HTTPS origin")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("read gateway CA")
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid gateway CA")
		}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func randomState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func rpcError(err error) error {
	if err == nil {
		return nil
	}
	var rpcErr *connect.Error
	if errors.As(err, &rpcErr) {
		for _, detail := range rpcErr.Details() {
			value, detailErr := detail.Value()
			if d, ok := value.(*v1.ErrorDetail); detailErr == nil && ok && d.Reason == "AUDIT_RESULT_UNAVAILABLE" {
				return errors.New("gateway result audit unavailable; operation may have committed")
			}
		}
	}
	return fmt.Errorf("gateway request failed (%s)", connect.CodeOf(err))
}

func NewLoginCmd() *cobra.Command {
	var gateway, ca, provider, username string
	var noBrowser, passwordStdin bool
	cmd := &cobra.Command{Use: "login", Short: "Create a seven-day CLI session using OIDC or LDAP", Args: cobra.NoArgs, SilenceUsage: true, RunE: func(c *cobra.Command, _ []string) error {
		client, err := gatewayClient(gateway, ca)
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		auth := rpc.NewAuthServiceClient(client, gateway)
		methods, err := auth.GetLoginMethods(c.Context(), connect.NewRequest(&v1.GetLoginMethodsRequest{}))
		if err != nil {
			return rpcError(err)
		}
		var method *v1.LoginMethod
		for _, m := range methods.Msg.Methods {
			if m.ProviderId == provider || provider == "" && len(methods.Msg.Methods) == 1 {
				method = m
			}
		}
		if method == nil {
			return errors.New("select a login provider with --provider")
		}
		var token string
		var session *v1.CliSession
		switch method.Kind {
		case "ldap":
			if username == "" {
				return errors.New("LDAP requires --username")
			}
			password, err := readPassword(c, passwordStdin)
			if err != nil {
				return err
			}
			response, err := auth.LoginLdap(c.Context(), connect.NewRequest(&v1.LoginLdapRequest{ProviderId: method.ProviderId, Username: username, Password: password, Client: v1.LoginClient_LOGIN_CLIENT_CLI}))
			if err != nil {
				return rpcError(err)
			}
			token, session = response.Msg.GetCliSessionToken(), response.Msg.CliSession
		case "oidc":
			var err error
			session, token, err = oidcLogin(c, auth, gateway, method.ProviderId, noBrowser)
			if err != nil {
				return err
			}
		default:
			return errors.New("unsupported login provider")
		}
		if token == "" || session == nil || session.ExpiresAt == nil {
			return errors.New("gateway did not return a CLI session")
		}
		if ca != "" {
			ca, err = filepath.Abs(ca)
			if err != nil {
				return err
			}
		}
		if err := saveCredentials(credentials{Gateway: gateway, CAFile: ca, Token: token, ExpiresAt: session.ExpiresAt.AsTime()}); err != nil {
			return err
		}
		_, err = fmt.Fprintf(c.OutOrStdout(), "Logged in; session expires %s\n", session.ExpiresAt.AsTime().Format(time.RFC3339))
		return err
	}}
	cmd.Flags().StringVar(&gateway, "gateway", "", "HTTPS gateway origin")
	cmd.Flags().StringVar(&ca, "ca-file", "", "Additional trusted CA certificate")
	cmd.Flags().StringVar(&provider, "provider", "", "Login provider ID")
	cmd.Flags().StringVar(&username, "username", "", "LDAP username")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the OIDC login URL without opening a browser")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read the LDAP password from stdin")
	return cmd
}
func readPassword(c *cobra.Command, stdin bool) (string, error) {
	input := c.InOrStdin()
	if !stdin {
		file, ok := input.(*os.File)
		if !ok {
			return "", errors.New("use --password-stdin for non-terminal input")
		}
		original, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
		if err != nil {
			return "", errors.New("use --password-stdin for non-terminal input")
		}
		hidden := *original
		hidden.Lflag &^= unix.ECHO
		if err := unix.IoctlSetTermios(int(file.Fd()), unix.TCSETS, &hidden); err != nil {
			return "", err
		}
		defer unix.IoctlSetTermios(int(file.Fd()), unix.TCSETS, original)
		fmt.Fprint(c.ErrOrStderr(), "LDAP password: ")
		defer fmt.Fprintln(c.ErrOrStderr())
	}
	// main cancels the command context on SIGINT instead of exiting, so the
	// prompt waits on it too; the deferred restore then turns echo back on.
	// A cancelled read is abandoned; the process exits after the command.
	ctx := c.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	type result struct {
		line string
		err  error
	}
	read := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(input, 4097)).ReadString('\n')
		read <- result{line, err}
	}()
	var line string
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-read:
		if r.err != nil && r.err != io.EOF {
			return "", r.err
		}
		line = r.line
	}
	if len(line) > 4096 {
		return "", errors.New("password exceeds input limit")
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}
func oidcLogin(c *cobra.Command, auth rpc.AuthServiceClient, gateway, provider string, noBrowser bool) (*v1.CliSession, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	defer listener.Close()
	state, pv := randomState(), oauth2.GenerateVerifier()
	callback := "http://" + listener.Addr().String() + "/callback"
	digest := sha256.Sum256([]byte(pv))
	result, err := auth.BeginOidcLogin(c.Context(), connect.NewRequest(&v1.BeginOidcLoginRequest{ProviderId: provider, Client: v1.LoginClient_LOGIN_CLIENT_CLI, CliLoopbackUri: callback, CliState: state, CliCodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:])}))
	if err != nil {
		return nil, "", rpcError(err)
	}
	link, err := url.Parse(result.Msg.AuthorizationUrl)
	base, _ := url.Parse(gateway)
	if err != nil || link.Scheme != "https" || link.Host != base.Host || link.User != nil || link.Path != "/auth/oidc/start" {
		return nil, "", errors.New("invalid gateway login URL")
	}
	codes := make(chan string, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/callback" || len(q) != 2 || q.Get("state") != state || q.Get("code") == "" {
			http.Error(w, "Invalid login callback", http.StatusBadRequest)
			return
		}
		select {
		case codes <- q.Get("code"):
			fmt.Fprintln(w, "Login callback received. Return to the CLI.")
		default:
			http.Error(w, "Callback already received", http.StatusConflict)
		}
	})}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	fmt.Fprintln(c.OutOrStdout(), result.Msg.AuthorizationUrl)
	if !noBrowser {
		if err := exec.Command("xdg-open", result.Msg.AuthorizationUrl).Run(); err != nil {
			fmt.Fprintln(c.ErrOrStderr(), "Open the login URL in your browser.")
		}
	}
	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Minute)
	defer cancel()
	var code string
	select {
	case code = <-codes:
	case <-ctx.Done():
		return nil, "", errors.New("OIDC login timed out or was canceled")
	}
	response, err := auth.ExchangeCliSession(ctx, connect.NewRequest(&v1.ExchangeCliSessionRequest{Code: code, CodeVerifier: pv}))
	if err != nil {
		return nil, "", rpcError(err)
	}
	return response.Msg.Session, response.Msg.SessionToken, nil
}

func outputProto(c *cobra.Command, m proto.Message) error {
	b, err := protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}.Marshal(m)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.OutOrStdout(), string(b))
	return err
}
func readRules(path string) (*v1.PolicyRules, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	var object map[string]any
	if err := d.Decode(&object); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("one YAML document required")
	}
	if rules, ok := object["rules"].([]any); ok {
		for _, raw := range rules {
			if rule, ok := raw.(map[string]any); ok {
				switch rule["effect"] {
				case "allow":
					rule["effect"] = "POLICY_EFFECT_ALLOW"
				case "deny":
					rule["effect"] = "POLICY_EFFECT_DENY"
				}
			}
		}
	}
	data, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	p := &v1.PolicyRules{}
	if err := protojson.Unmarshal(data, p); err != nil {
		return nil, errors.New("invalid structured policy rules")
	}
	return p, nil
}
func NewPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Read, simulate and apply structured gateway policies", SilenceUsage: true}
	var asJSON bool
	cmd.PersistentFlags().BoolVar(&asJSON, "json", false, "Output JSON")
	get := &cobra.Command{Use: "get", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		cfg, err := loadCredentials()
		if err != nil {
			return err
		}
		client, err := gatewayClient(cfg.Gateway, cfg.CAFile)
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		p := rpc.NewPolicyServiceClient(client, cfg.Gateway, connect.WithInterceptors(bearer(cfg.Token)))
		response, err := p.GetPolicy(c.Context(), connect.NewRequest(&v1.GetPolicyRequest{}))
		if err != nil {
			return rpcError(err)
		}
		if asJSON {
			return outputProto(c, response.Msg.Policy)
		}
		b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(response.Msg.Policy.Rules)
		if err != nil {
			return err
		}
		var object map[string]any
		if err := json.Unmarshal(b, &object); err != nil {
			return err
		}
		if rules, ok := object["rules"].([]any); ok {
			for _, raw := range rules {
				r := raw.(map[string]any)
				if r["effect"] == "POLICY_EFFECT_ALLOW" {
					r["effect"] = "allow"
				} else if r["effect"] == "POLICY_EFFECT_DENY" {
					r["effect"] = "deny"
				}
			}
		}
		b, err = yaml.Marshal(object)
		if err != nil {
			return err
		}
		_, err = c.OutOrStdout().Write(b)
		return err
	}}
	cmd.AddCommand(get)
	for _, verb := range []string{"apply", "test"} {
		var path, reason string
		action := &cobra.Command{Use: verb, Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadCredentials()
			if err != nil {
				return err
			}
			client, err := gatewayClient(cfg.Gateway, cfg.CAFile)
			if err != nil {
				return err
			}
			defer client.CloseIdleConnections()
			p := rpc.NewPolicyServiceClient(client, cfg.Gateway, connect.WithInterceptors(bearer(cfg.Token)))
			current, err := p.GetPolicy(c.Context(), connect.NewRequest(&v1.GetPolicyRequest{}))
			if err != nil {
				return rpcError(err)
			}
			rules := current.Msg.Policy.Rules
			if path != "" {
				rules, err = readRules(path)
				if err != nil {
					return err
				}
			} else if verb == "apply" {
				return errors.New("apply requires -f rules.yaml")
			}
			tested, err := p.TestPolicy(c.Context(), connect.NewRequest(&v1.TestPolicyRequest{BaseVersion: current.Msg.Policy.Version, Candidate: &v1.TestPolicyRequest_Rules{Rules: rules}}))
			if err != nil {
				return rpcError(err)
			}
			if err := outputProto(c, tested.Msg.Test); err != nil {
				return err
			}
			cursor := ""
			for {
				changes, err := p.GetPolicyTestChanges(c.Context(), connect.NewRequest(&v1.GetPolicyTestChangesRequest{TestId: tested.Msg.Test.TestId, Page: &v1.PageRequest{PageToken: cursor}}))
				if err != nil {
					return rpcError(err)
				}
				for _, change := range changes.Msg.Changes {
					if err := outputProto(c, change); err != nil {
						return err
					}
				}
				cursor = changes.Msg.GetPage().GetNextPageToken()
				if cursor == "" {
					break
				}
			}
			if verb == "test" {
				return nil
			}
			saved, err := p.SavePolicy(c.Context(), connect.NewRequest(&v1.SavePolicyRequest{BaseVersion: current.Msg.Policy.Version, Rules: rules, TestId: tested.Msg.Test.TestId, Reason: reason}))
			if err != nil {
				return rpcError(err)
			}
			return outputProto(c, saved.Msg.Policy)
		}}
		action.Flags().StringVarP(&path, "file", "f", "", "Structured rules YAML")
		action.Flags().StringVar(&reason, "reason", "", "Audit reason for saving the policy")
		cmd.AddCommand(action)
	}
	return cmd
}
func bearer(token string) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			r.Header().Set("Authorization", "Bearer "+token)
			return next(ctx, r)
		}
	})
}
