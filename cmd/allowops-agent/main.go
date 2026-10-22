package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/liubing0806/allowops/internal/agent"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	command := newCommand()
	if err := command.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	root := &cobra.Command{Use: "allowops-agent", Version: version, SilenceUsage: true, SilenceErrors: true}
	root.SetVersionTemplate("{{.Version}}\n")
	var upstream, pin string
	join := &cobra.Command{Use: "join", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		token, err := readJoinToken(cmd)
		if err != nil {
			return err
		}
		if err := agent.CheckCommandUser(true); err != nil {
			return err
		}
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		value, err := agent.Join(cmd.Context(), agent.Config{Upstream: upstream, CAPin: pin}, token, hostname, agent.DataDirectory)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"host_id": value.HostID, "hostname": value.Hostname})
	}}
	join.Flags().StringVar(&upstream, "upstream", "", "Gateway TLS address")
	join.Flags().String("token", "", "Join token (visible in process arguments)")
	join.Flags().String("token-file", "", "Read join token from a file (maximum 4 KiB)")
	join.Flags().Bool("token-stdin", false, "Read join token from stdin (maximum 4 KiB)")
	join.Flags().StringVar(&pin, "ca-pin", "", "sha256: fingerprint of CA certificate DER")
	for _, name := range []string{"upstream", "ca-pin"} {
		_ = join.MarkFlagRequired(name)
	}
	run := &cobra.Command{Use: "run", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := agent.CheckCommandUser(false); err != nil {
			return err
		}
		config, err := agent.LoadConfig(agent.ConfigFile)
		if err != nil {
			return err
		}
		service, err := agent.New(config, agent.Options{Version: version})
		if err != nil {
			return err
		}
		err = service.Run(cmd.Context())
		if cmd.Context().Err() != nil {
			return nil
		}
		return err
	}}
	status := &cobra.Command{Use: "status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		value, err := agent.Status(agent.DataDirectory)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(value)
	}}
	root.AddCommand(join, run, status)
	return root
}
