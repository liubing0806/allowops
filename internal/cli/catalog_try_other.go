//go:build !linux

package cli

import (
	"errors"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/spf13/cobra"
)

func newTryCmd(func(*cobra.Command) (*catalog.Catalog, error)) *cobra.Command {
	cmd := &cobra.Command{Use: "try <action>", Args: cobra.ExactArgs(1), RunE: func(*cobra.Command, []string) error {
		return errors.New("catalog try requires Linux")
	}}
	cmd.Flags().StringArray("param", nil, "Action parameter name=value; repeat for each parameter")
	return cmd
}
