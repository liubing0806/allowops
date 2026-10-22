package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/params"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func jobClients() (rpc.JobServiceClient, rpc.CatalogServiceClient, error) {
	c, err := loadCredentials()
	if err != nil {
		return nil, nil, err
	}
	client, err := gatewayClient(c.Gateway, c.CAFile)
	if err != nil {
		return nil, nil, err
	}
	// Run/Get may wait for the gateway's configured maximum of 120 seconds.
	client.Timeout = 130 * time.Second
	opts := connect.WithInterceptors(bearer(c.Token))
	return rpc.NewJobServiceClient(client, c.Gateway, opts), rpc.NewCatalogServiceClient(client, c.Gateway, opts), nil
}

func jobError(err error) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*connect.Error); ok {
		for _, d := range e.Details() {
			v, err := d.Value()
			if err != nil {
				continue
			}
			if detail, ok := v.(*v1.ErrorDetail); ok {
				b, _ := protojson.Marshal(detail)
				return fmt.Errorf("gateway request failed (%s): %s", e.Code(), b)
			}
		}
	}
	return rpcError(err)
}

func printJob(c *cobra.Command, j *v1.Job, summary *v1.JobSummary) error {
	w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "JOB\tACTION\tSTATUS\tTASKS")
	fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", j.GetJobId(), j.GetAction(), strings.ToLower(strings.TrimPrefix(j.GetStatus().String(), "JOB_STATUS_")), j.GetTotalTasks())
	if summary != nil {
		fmt.Fprintln(w, "HOSTS\tEXIT\tSTDOUT\tSTDERR\tTRUNCATED")
		for _, g := range summary.Groups {
			exit := "-"
			if g.ExitCode != nil {
				exit = strconv.FormatInt(int64(*g.ExitCode), 10)
			}
			fmt.Fprintf(w, "%s (%d)\t%s\t%q\t%q\t%t\n", strings.Join(g.Hosts, ","), g.HostCount, exit, g.Stdout, g.Stderr, g.Truncated)
		}
	}
	return w.Flush()
}

func printJobJSON(c *cobra.Command, m proto.Message) error {
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.OutOrStdout(), string(b))
	return err
}

func typedParameters(raw []string, a catalog.Action) ([]byte, error) {
	defs, err := catalog.ParameterDefinitions(a)
	if err != nil {
		return nil, err
	}
	values := map[string]any{}
	for _, p := range raw {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("--param requires name=value")
		}
		def, ok := defs[k]
		if !ok {
			return nil, fmt.Errorf("unknown parameter %s", k)
		}
		if _, ok := values[k]; ok {
			return nil, fmt.Errorf("duplicate parameter %s", k)
		}
		switch def.Type {
		case params.Int:
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parameter %s requires integer", k)
			}
			values[k] = n
		case params.Bool:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("parameter %s requires boolean", k)
			}
			values[k] = b
		case params.StringArray:
			var list []string
			if err := json.Unmarshal([]byte(v), &list); err != nil || list == nil {
				return nil, fmt.Errorf("parameter %s requires JSON string array", k)
			}
			values[k] = list
		default:
			values[k] = v
		}
	}
	return json.Marshal(values)
}

func NewRunCmd() *cobra.Command {
	var selector, reason, responseFormat string
	var names, raw []string
	var expected uint64
	var wait, batch, failures uint32
	var jsonOutput bool
	c := &cobra.Command{Use: "run <action>", Short: "Run a signed action through the gateway job flow", Args: cobra.ExactArgs(1), SilenceUsage: true, RunE: func(c *cobra.Command, args []string) error {
		if (selector == "") == (len(names) == 0) {
			return fmt.Errorf("exactly one of --selector or --hosts required")
		}
		if selector != "" && !c.Flags().Changed("expected-count") {
			return fmt.Errorf("--expected-count required with --selector")
		}
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("--reason required")
		}
		jobs, catalogs, err := jobClients()
		if err != nil {
			return err
		}
		r := &v1.RunJobRequest{Action: args[0], Reason: reason, ResponseFormat: responseFormat, Params: &v1.Parameters{Json: []byte("{}")}, Targets: &v1.HostTargets{}}
		if selector != "" {
			r.Targets.Selection = &v1.HostTargets_Selector{Selector: selector}
		} else {
			r.Targets.Selection = &v1.HostTargets_Hosts{Hosts: &v1.HostNames{Names: names}}
		}
		if c.Flags().Changed("expected-count") {
			r.ExpectedCount = &expected
		}
		if c.Flags().Changed("wait-seconds") {
			r.WaitSeconds = &wait
		}
		if c.Flags().Changed("batch-size") {
			r.BatchSize = &batch
		}
		if c.Flags().Changed("max-failures") {
			r.MaxFailures = &failures
		}
		if len(raw) > 0 {
			schema, err := catalogs.GetAction(c.Context(), connect.NewRequest(&v1.GetActionRequest{Action: args[0]}))
			if err != nil {
				switch connect.CodeOf(err) {
				case connect.CodePermissionDenied:
					return fmt.Errorf("reading action schema requires view_catalog permission")
				case connect.CodeNotFound:
					return fmt.Errorf("action schema not found")
				default:
					return jobError(err)
				}
			}
			var a catalog.Action
			if err := json.Unmarshal(schema.Msg.DefinitionJson, &a); err != nil {
				return fmt.Errorf("invalid gateway action schema")
			}
			r.Params.Json, err = typedParameters(raw, a)
			if err != nil {
				return err
			}
		}
		result, err := jobs.RunJob(c.Context(), connect.NewRequest(r))
		if err != nil {
			return jobError(err)
		}
		if jsonOutput {
			err = printJobJSON(c, result.Msg)
		} else {
			err = printJob(c, result.Msg.Job, result.Msg.Summary)
		}
		if err != nil {
			return err
		}
		job := result.Msg.Job
		status := strings.ToLower(strings.TrimPrefix(job.GetStatus().String(), "JOB_STATUS_"))
		switch job.GetStatus() {
		case v1.JobStatus_JOB_STATUS_SUCCEEDED:
			return nil
		case v1.JobStatus_JOB_STATUS_FAILED, v1.JobStatus_JOB_STATUS_PARTIALLY_FAILED, v1.JobStatus_JOB_STATUS_CANCELLED, v1.JobStatus_JOB_STATUS_DENIED:
			return fmt.Errorf("job %s completed with status %s", job.GetJobId(), status)
		case v1.JobStatus_JOB_STATUS_QUEUED, v1.JobStatus_JOB_STATUS_RUNNING:
			_, err = fmt.Fprintf(c.ErrOrStderr(), "Job %s has not completed (status: %s).\n", job.GetJobId(), status)
			return err
		default:
			// UNSPECIFIED, statuses newer than this CLI and a response without a Job.
			return fmt.Errorf("job %s has unknown status: %s", job.GetJobId(), status)
		}
	}}
	c.Flags().StringVar(&selector, "selector", "", "Comma-separated key=value conjunctions")
	c.Flags().StringSliceVar(&names, "hosts", nil, "Explicit hostnames")
	c.Flags().Uint64Var(&expected, "expected-count", 0, "Required selector match count")
	c.Flags().StringArrayVar(&raw, "param", nil, "Action parameter name=value (arrays use JSON)")
	c.Flags().StringVar(&reason, "reason", "", "Required audit reason")
	c.Flags().Uint32Var(&wait, "wait-seconds", 30, "Response wait; 0 returns immediately")
	c.Flags().Uint32Var(&batch, "batch-size", 20, "Tighten the signed/default batch size")
	c.Flags().Uint32Var(&failures, "max-failures", 5, "Tighten the signed/default failure threshold")
	c.Flags().StringVar(&responseFormat, "response-format", "concise", "concise or detailed")
	c.Flags().BoolVar(&jsonOutput, "json", false, "Print JSON")
	return c
}

func NewJobsCmd() *cobra.Command {
	var jsonOutput bool
	root := &cobra.Command{Use: "jobs", Short: "List, inspect, read output or cancel jobs", SilenceUsage: true}
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Print JSON")
	var pageSize uint32
	var pageToken string
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		jobs, _, err := jobClients()
		if err != nil {
			return err
		}
		r, err := jobs.ListJobs(c.Context(), connect.NewRequest(&v1.ListJobsRequest{Page: &v1.PageRequest{PageSize: pageSize, PageToken: pageToken}}))
		if err != nil {
			return jobError(err)
		}
		if jsonOutput {
			return printJobJSON(c, r.Msg)
		}
		w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "JOB\tACTION\tSTATUS\tTASKS")
		for _, j := range r.Msg.Jobs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", j.GetJobId(), j.GetAction(), strings.ToLower(strings.TrimPrefix(j.GetStatus().String(), "JOB_STATUS_")), j.GetTotalTasks())
		}
		return w.Flush()
	}}
	list.Flags().Uint32Var(&pageSize, "page-size", 50, "Page size (maximum 200)")
	list.Flags().StringVar(&pageToken, "page-token", "", "Page cursor")
	var wait uint32
	var responseFormat string
	get := &cobra.Command{Use: "get <job-id>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		jobs, _, err := jobClients()
		if err != nil {
			return err
		}
		r, err := jobs.GetJob(c.Context(), connect.NewRequest(&v1.GetJobRequest{JobId: args[0], WaitSeconds: &wait, ResponseFormat: responseFormat}))
		if err != nil {
			return jobError(err)
		}
		if jsonOutput {
			return printJobJSON(c, r.Msg)
		}
		return printJob(c, r.Msg.Job, r.Msg.Summary)
	}}
	get.Flags().Uint32Var(&wait, "wait-seconds", 0, "Wait for terminal job status")
	get.Flags().StringVar(&responseFormat, "response-format", "concise", "concise or detailed")
	cancel := &cobra.Command{Use: "cancel <job-id>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		jobs, _, err := jobClients()
		if err != nil {
			return err
		}
		r, err := jobs.CancelJob(c.Context(), connect.NewRequest(&v1.CancelJobRequest{JobId: args[0]}))
		if err != nil {
			return jobError(err)
		}
		if jsonOutput {
			return printJobJSON(c, r.Msg)
		}
		return printJob(c, r.Msg.Job, nil)
	}}
	var hostname, stream string
	var step uint32
	var offset uint64
	var limit uint32
	out := &cobra.Command{Use: "output <job-id>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		jobs, _, err := jobClients()
		if err != nil {
			return err
		}
		kind := v1.OutputStream_OUTPUT_STREAM_STDOUT
		if stream == "stderr" {
			kind = v1.OutputStream_OUTPUT_STREAM_STDERR
		} else if stream != "stdout" {
			return fmt.Errorf("--stream must be stdout or stderr")
		}
		r := &v1.GetJobOutputRequest{JobId: args[0], Hostname: hostname, Stream: kind, Offset: offset, LimitBytes: limit}
		if c.Flags().Changed("step") {
			r.StepIndex = &step
		}
		response, err := jobs.GetJobOutput(c.Context(), connect.NewRequest(r))
		if err != nil {
			return jobError(err)
		}
		if jsonOutput {
			return printJobJSON(c, response.Msg)
		}
		w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "HOST\tSTREAM\tNEXT OFFSET\tEOF\tSTORED\tTRUST")
		fmt.Fprintf(w, "%s\t%s\t%d\t%t\t%t\tuntrusted\n", hostname, stream, response.Msg.NextOffset, response.Msg.Eof, response.Msg.OutputStored)
		if err := w.Flush(); err != nil {
			return err
		}
		_, err = c.OutOrStdout().Write(response.Msg.Data)
		return err
	}}
	out.Flags().StringVar(&hostname, "host", "", "Required hostname")
	_ = out.MarkFlagRequired("host")
	out.Flags().StringVar(&stream, "stream", "stdout", "stdout or stderr")
	out.Flags().Uint32Var(&step, "step", 0, "Zero-based step index for steps actions")
	out.Flags().Uint64Var(&offset, "offset", 0, "Byte offset")
	out.Flags().Uint32Var(&limit, "limit", 16<<10, "Output page bytes (maximum 24576)")
	root.AddCommand(list, get, out, cancel)
	return root
}
