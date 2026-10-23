package cli

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"
)

type remoteFlags struct{ gateway, ca, tokenEnv string }

func (f *remoteFlags) flags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&f.gateway, "gateway", "", "HTTPS gateway origin (defaults to login credentials)")
	cmd.PersistentFlags().StringVar(&f.ca, "ca-file", "", "Additional trusted CA certificate")
	cmd.PersistentFlags().StringVar(&f.tokenEnv, "token-env", "", "Environment variable containing a service account token")
}

func (f *remoteFlags) client() (*http.Client, credentials, error) {
	var cfg credentials
	var err error
	if f.tokenEnv != "" {
		cfg.Token = os.Getenv(f.tokenEnv)
		if cfg.Token == "" {
			return nil, cfg, errors.New("service account token environment variable is empty")
		}
		cfg.Gateway = f.gateway
		cfg.CAFile = f.ca
	} else {
		cfg, err = loadCredentials()
		if err != nil {
			return nil, cfg, err
		}
		if f.gateway != "" {
			cfg.Gateway = f.gateway
		}
		if f.ca != "" {
			cfg.CAFile = f.ca
		}
	}
	client, err := gatewayClient(cfg.Gateway, cfg.CAFile)
	return client, cfg, err
}

func NewHostsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "hosts", Short: "List, label and delete registered hosts", SilenceUsage: true}
	var asJSON bool
	cmd.PersistentFlags().BoolVar(&asJSON, "json", false, "Output JSON")
	remote := &remoteFlags{}
	remote.flags(cmd)
	var selector string
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		client, cfg, err := remote.client()
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		api := rpc.NewHostServiceClient(client, cfg.Gateway, connect.WithInterceptors(bearer(cfg.Token)))
		items := []*v1.Host{}
		cursor := ""
		for {
			r, err := api.ListHosts(c.Context(), connect.NewRequest(&v1.ListHostsRequest{Query: &v1.HostQuery{Selector: selector}, Page: &v1.PageRequest{PageToken: cursor}}))
			if err != nil {
				return rpcError(err)
			}
			items = append(items, r.Msg.Hosts...)
			cursor = r.Msg.GetPage().GetNextPageToken()
			if cursor == "" {
				break
			}
		}
		if asJSON {
			return outputProto(c, &v1.ListHostsResponse{Hosts: items, TotalCount: uint64(len(items))})
		}
		w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "HOSTNAME\tONLINE\tAGENT VERSION\tREVISION")
		for _, h := range items {
			fmt.Fprintf(w, "%s\t%t\t%s\t%s\n", h.Hostname, h.Online, h.AgentVersion, h.Revision)
		}
		return w.Flush()
	}}
	list.Flags().StringVar(&selector, "selector", "", "Comma-separated key=value conditions")
	cmd.AddCommand(list)
	var labelSelector string
	var expected uint64
	var set, remove []string
	label := &cobra.Command{Use: "label [hostname...]", Args: cobra.ArbitraryArgs, RunE: func(c *cobra.Command, names []string) error {
		if (len(names) == 0) == (labelSelector == "") {
			return errors.New("specify hostnames or --selector")
		}
		changes := &v1.LabelChanges{Set: map[string]string{}, Remove: remove}
		for _, part := range set {
			key, value, ok := strings.Cut(part, "=")
			if !ok || key == "" {
				return errors.New("--set requires key=value")
			}
			if _, exists := changes.Set[key]; exists {
				return errors.New("duplicate --set key")
			}
			changes.Set[key] = value
		}
		if len(set)+len(remove) == 0 {
			return errors.New("--set or --remove required")
		}
		if labelSelector != "" && !c.Flags().Changed("expected-count") {
			return errors.New("selector requires --expected-count")
		}
		client, cfg, err := remote.client()
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		api := rpc.NewHostServiceClient(client, cfg.Gateway, connect.WithInterceptors(bearer(cfg.Token)))
		targets := &v1.HostTargets{}
		revisions := []*v1.HostRevision{}
		if labelSelector != "" {
			targets.Selection = &v1.HostTargets_Selector{Selector: labelSelector}
			cursor := ""
			for {
				r, err := api.ListHosts(c.Context(), connect.NewRequest(&v1.ListHostsRequest{Query: &v1.HostQuery{Selector: labelSelector}, Page: &v1.PageRequest{PageToken: cursor}}))
				if err != nil {
					return rpcError(err)
				}
				for _, h := range r.Msg.Hosts {
					revisions = append(revisions, &v1.HostRevision{HostId: h.HostId, Revision: h.Revision})
				}
				cursor = r.Msg.GetPage().GetNextPageToken()
				if cursor == "" {
					break
				}
			}
		} else {
			targets.Selection = &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: names}}
			for _, name := range names {
				r, err := api.GetHost(c.Context(), connect.NewRequest(&v1.GetHostRequest{Hostname: name}))
				if err != nil {
					return rpcError(err)
				}
				revisions = append(revisions, &v1.HostRevision{HostId: r.Msg.Host.HostId, Revision: r.Msg.Host.Revision})
			}
			if !c.Flags().Changed("expected-count") {
				expected = uint64(len(names))
			}
		}
		r, err := api.SetHostLabels(c.Context(), connect.NewRequest(&v1.SetHostLabelsRequest{Targets: targets, ExpectedCount: expected, Changes: changes, ExpectedRevisions: revisions}))
		if err != nil {
			return rpcError(err)
		}
		if asJSON {
			return outputProto(c, r.Msg)
		}
		fmt.Fprintln(c.OutOrStdout(), "UPDATED HOSTS")
		_, err = fmt.Fprintln(c.OutOrStdout(), r.Msg.UpdatedCount)
		return err
	}}
	label.Flags().StringVar(&labelSelector, "selector", "", "Comma-separated key=value conditions")
	label.Flags().Uint64Var(&expected, "expected-count", 0, "Exact number of targets")
	label.Flags().StringArrayVar(&set, "set", nil, "Set an authorization label key=value (repeatable)")
	label.Flags().StringArrayVar(&remove, "remove", nil, "Remove a label key (repeatable)")
	cmd.AddCommand(label)
	del := &cobra.Command{Use: "delete <hostname>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, names []string) error {
		client, cfg, err := remote.client()
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		api := rpc.NewHostServiceClient(client, cfg.Gateway, connect.WithInterceptors(bearer(cfg.Token)))
		h, err := api.GetHost(c.Context(), connect.NewRequest(&v1.GetHostRequest{Hostname: names[0]}))
		if err != nil {
			return rpcError(err)
		}
		r, err := api.DeleteHost(c.Context(), connect.NewRequest(&v1.DeleteHostRequest{HostId: h.Msg.Host.HostId, ExpectedRevision: h.Msg.Host.Revision}))
		if err != nil {
			return rpcError(err)
		}
		if asJSON {
			return outputProto(c, r.Msg)
		}
		fmt.Fprintln(c.OutOrStdout(), "DELETED HOST")
		_, err = fmt.Fprintln(c.OutOrStdout(), names[0])
		return err
	}}
	cmd.AddCommand(del)
	return cmd
}

func NewJoinTokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "jointoken", Short: "Create a bounded host registration token", SilenceUsage: true}
	remote := &remoteFlags{}
	remote.flags(cmd)
	var asJSON bool
	cmd.PersistentFlags().BoolVar(&asJSON, "json", false, "Output JSON")
	var uses uint32
	var ttl time.Duration
	create := &cobra.Command{Use: "create", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if uses == 0 {
			return errors.New("--uses must be positive")
		}
		request := &v1.CreateJoinTokenRequest{MaxUses: uses}
		if c.Flags().Changed("ttl") {
			if ttl <= 0 {
				return errors.New("--ttl must be positive")
			}
			request.Ttl = durationpb.New(ttl)
		}
		client, cfg, err := remote.client()
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		api := rpc.NewJoinTokenServiceClient(client, cfg.Gateway, connect.WithInterceptors(bearer(cfg.Token)))
		r, err := api.CreateJoinToken(c.Context(), connect.NewRequest(request))
		if err != nil {
			return rpcError(err)
		}
		if asJSON {
			return outputProto(c, r.Msg)
		}
		w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "TOKEN ID\tUSES\tEXPIRES\tUPSTREAM\tCA PIN\tSECRET")
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n", r.Msg.Token.TokenId, r.Msg.Token.MaxUses, r.Msg.Token.ExpiresAt.AsTime().Format(time.RFC3339), r.Msg.Upstream, r.Msg.CaPin, r.Msg.Secret)
		return w.Flush()
	}}
	create.Flags().Uint32Var(&uses, "uses", 1, "Maximum registrations")
	create.Flags().DurationVar(&ttl, "ttl", 0, "Token validity duration (gateway default if omitted)")
	cmd.AddCommand(create)
	return cmd
}
