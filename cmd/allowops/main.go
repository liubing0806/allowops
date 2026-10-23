package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/liubing0806/allowops/internal/cli"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	command := &cobra.Command{
		Use:     "allowops",
		Short:   "Operations gateway CLI",
		Version: version,
	}
	command.SetVersionTemplate("{{.Version}}\n")
	command.AddCommand(cli.NewCatalogCmd(), cli.NewAuditCmd())
	command.AddCommand(cli.NewLoginCmd(), cli.NewPolicyCmd(), cli.NewHostsCmd(), cli.NewJoinTokenCmd())
	command.AddCommand(cli.NewRunCmd(), cli.NewJobsCmd())
	// Actions run in their own process group and are killed only when the
	// command context ends, so SIGINT/SIGTERM must cancel it instead of
	// terminating the CLI and orphaning the group.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// A second signal then takes the default action, so a stuck command can still be aborted.
	go func() { <-ctx.Done(); stop() }()
	err := command.ExecuteContext(ctx)
	stop()
	if err != nil {
		os.Exit(1)
	}
}
