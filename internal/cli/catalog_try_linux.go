package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/spf13/cobra"
)

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
