package main

import (
	"os"

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
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}
