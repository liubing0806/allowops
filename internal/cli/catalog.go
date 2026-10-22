package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/spf13/cobra"
)

func NewCatalogCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{Use: "catalog", Short: "Validate, build, sign and try local action catalogs", SilenceUsage: true, SilenceErrors: true}
	cmd.AddCommand(newPublishCmd())
	cmd.PersistentFlags().StringVar(&dir, "dir", ".", "Local catalog directory")
	load := func(c *cobra.Command) (*catalog.Catalog, error) {
		result, err := catalog.Load(dir)
		if err == nil {
			for _, warning := range result.Warnings {
				fmt.Fprintln(c.ErrOrStderr(), "warning:", warning)
			}
		}
		return result, err
	}
	validate := &cobra.Command{Use: "validate [directory]", Args: cobra.MaximumNArgs(1), RunE: func(c *cobra.Command, args []string) error {
		if len(args) == 1 {
			dir = args[0]
		}
		result, err := load(c)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(c.OutOrStdout(), "catalog %s: %d actions valid\n", result.Config.CatalogID, len(result.Actions))
		return err
	}}
	var output, gitCommit string
	var ttl time.Duration
	build := &cobra.Command{Use: "build", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		result, err := load(c)
		if err != nil {
			return err
		}
		commit := gitCommit
		if commit == "" {
			command := exec.Command("/usr/bin/git", "-C", dir, "rev-parse", "HEAD")
			data, err := command.Output()
			if err != nil {
				return fmt.Errorf("cannot read Git commit; supply --git-commit: %w", err)
			}
			commit = strings.TrimSpace(string(data))
		}
		p, err := catalog.Build(result, catalog.BuildOptions{Now: time.Now(), TTL: ttl, GitCommit: commit})
		if err != nil {
			return err
		}
		data, err := catalog.CanonicalJSON(p)
		if err != nil {
			return err
		}
		return writeOutput(c, output, data)
	}}
	build.Flags().StringVar(&output, "out", "catalog.json", "Output file, or - for stdout")
	build.Flags().StringVar(&gitCommit, "git-commit", "", "Source Git commit (defaults to repository HEAD)")
	build.Flags().DurationVar(&ttl, "ttl", 90*24*time.Hour, "Catalog validity period from build-time created_at (default 90 days)")
	cmd.AddCommand(newKeygenCmd(), validate, build, newSignCmd(), newTryCmd(load))
	return cmd
}

func newKeygenCmd() *cobra.Command {
	var privateFile, publicFile string
	cmd := &cobra.Command{Use: "keygen", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if privateFile == publicFile {
			return fmt.Errorf("private and public key paths must differ")
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privatePEM, err := catalog.MarshalPrivateKey(private)
		if err != nil {
			return err
		}
		publicPEM, err := catalog.MarshalPublicKey(public)
		if err != nil {
			return err
		}
		if err := writeNew(privateFile, privatePEM, 0600); err != nil {
			return err
		}
		if err := writeNew(publicFile, publicPEM, 0644); err != nil {
			return err
		}
		_, err = fmt.Fprintln(c.OutOrStdout(), "keyid:", catalog.KeyID(public))
		return err
	}}
	cmd.Flags().StringVar(&privateFile, "private-key", "catalog-key.pem", "New PKCS8 private key file (0600)")
	cmd.Flags().StringVar(&publicFile, "public-key", "catalog-key.pub.pem", "New PKIX public key file")
	return cmd
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeOutput(cmd *cobra.Command, path string, data []byte) error {
	if path == "-" {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func newSignCmd() *cobra.Command {
	var input, output string
	var keyFiles []string
	cmd := &cobra.Command{Use: "sign", Short: "Sign a catalog without changing its build-time expiry", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if len(keyFiles) == 0 {
			return fmt.Errorf("at least one --key required")
		}
		data, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		p, err := catalog.ParsePackage(data)
		var envelope *catalog.Envelope
		if err != nil {
			envelope, err = catalog.ParseEnvelope(data)
			if err != nil {
				return err
			}
			payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
			if err != nil {
				return err
			}
			p, err = catalog.ParsePackage(payload)
			if err != nil {
				return err
			}
		}
		payload, err := catalog.CanonicalJSON(p)
		if err != nil {
			return err
		}
		for _, path := range keyFiles {
			keyData, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			key, err := catalog.ParsePrivateKey(keyData)
			if err != nil {
				return err
			}
			signingKey := catalog.SigningKey{PrivateKey: key}
			if envelope == nil {
				envelope, err = catalog.Sign(payload, signingKey)
			} else {
				existing, payloadErr := base64.StdEncoding.DecodeString(envelope.Payload)
				if payloadErr != nil {
					return payloadErr
				}
				if string(existing) != string(payload) {
					return fmt.Errorf("existing signed payload is not canonical")
				}
				err = catalog.AddSignature(envelope, signingKey)
			}
			if err != nil {
				return err
			}
		}
		data, err = catalog.CanonicalJSON(envelope)
		if err != nil {
			return err
		}
		return writeOutput(c, output, data)
	}}
	cmd.Flags().StringVar(&input, "in", "catalog.json", "Unsigned package or existing DSSE envelope")
	cmd.Flags().StringVar(&output, "out", "catalog.dsse.json", "Output file, or - for stdout")
	cmd.Flags().StringArrayVar(&keyFiles, "key", nil, "PKCS8 private key file; repeat for multiple signatures")
	return cmd
}

func newTryCmd(load func(*cobra.Command) (*catalog.Catalog, error)) *cobra.Command {
	var rawParams []string
	cmd := &cobra.Command{Use: "try <action>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		loaded, err := load(c)
		if err != nil {
			return err
		}
		a, exists := loaded.Actions[args[0]]
		if !exists {
			return fmt.Errorf("unknown action %q", args[0])
		}
		defs, err := catalog.ParameterDefinitions(a)
		if err != nil {
			return err
		}
		input := map[string]any{}
		for _, raw := range rawParams {
			name, value, ok := strings.Cut(raw, "=")
			if !ok {
				return fmt.Errorf("parameter must be name=value")
			}
			if _, duplicate := input[name]; duplicate {
				return fmt.Errorf("duplicate parameter %s", name)
			}
			def, declared := defs[name]
			if def.Type == params.Int || (!declared && (name == "tail" || name == "head")) {
				number, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					input[name] = value // The shared validator reports the declared bounds.
					continue
				}
				input[name] = number
			} else if def.Type == params.StringArray {
				var list []string
				if err := json.Unmarshal([]byte(value), &list); err != nil || list == nil {
					return fmt.Errorf("%s requires JSON string array", name)
				}
				input[name] = list
			} else if def.Type == params.Bool || (!declared && name == "count") {
				b, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("%s requires boolean", name)
				}
				input[name] = b
			} else {
				input[name] = value
			}
		}
		if a.RunAs != "" {
			fmt.Fprintf(c.ErrOrStderr(), "warning: run_as=%s; try executes as the current user\n", a.RunAs)
		}
		result, runErr := executor.Run(c.Context(), a, input, loaded.Config.Redact)
		response := struct {
			OK     bool   `json:"ok"`
			Action string `json:"action"`
			executor.Result
		}{OK: runErr == nil && result.ExitCode == 0, Action: a.Name, Result: result}
		if err := json.NewEncoder(c.OutOrStdout()).Encode(response); err != nil {
			return err
		}
		if runErr != nil {
			return runErr
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("action exited with code %d", result.ExitCode)
		}
		return nil
	}}
	cmd.Flags().StringArrayVar(&rawParams, "param", nil, "Action parameter name=value; repeat for each parameter")
	return cmd
}
