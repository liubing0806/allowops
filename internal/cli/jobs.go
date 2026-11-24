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

func cliGroupSeverity(s v1.GroupSeverity) string {
	switch s {
	case v1.GroupSeverity_GROUP_SEVERITY_FAILURE:
		return "failure"
	case v1.GroupSeverity_GROUP_SEVERITY_ANOMALY:
		return "anomaly"
	case v1.GroupSeverity_GROUP_SEVERITY_NORMAL:
		return "normal"
	default:
		return "-"
	}
}

func cliTaskStatus(s v1.TaskStatus) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "TASK_STATUS_"))
}

func validateCLIGrouping(grouping string) error {
	if grouping != "exact" && grouping != "normalized" {
		return fmt.Errorf("--grouping must be exact or normalized")
	}
	return nil
}

func printJob(c *cobra.Command, j *v1.Job, summary *v1.JobSummary) error {
	w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "JOB\tACTION\tSTATUS\tTASKS")
	fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", terminalText(j.GetJobId()), terminalText(j.GetAction()), strings.ToLower(strings.TrimPrefix(j.GetStatus().String(), "JOB_STATUS_")), j.GetTotalTasks())
	if summary != nil {
		hasSeverity := false
		for _, g := range summary.Groups {
			if g.GetSeverity() != v1.GroupSeverity_GROUP_SEVERITY_UNSPECIFIED || g.GetAnomalyReason() != "" {
				hasSeverity = true
				break
			}
		}
		if hasSeverity {
			fmt.Fprintln(w, "SEVERITY\tANOMALY\tHOSTS\tEXIT\tSTDOUT\tSTDERR\tTRUNCATED")
			for _, g := range summary.Groups {
				exit := "-"
				if g.ExitCode != nil {
					exit = strconv.FormatInt(int64(*g.ExitCode), 10)
				}
				anomaly := g.AnomalyReason
				if anomaly == "" {
					anomaly = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s (%d)\t%s\t%q\t%q\t%t\n", cliGroupSeverity(g.Severity), terminalText(anomaly), terminalText(strings.Join(g.Hosts, ",")), g.HostCount, exit, g.Stdout, g.Stderr, g.Truncated)
			}
		} else {
			fmt.Fprintln(w, "HOSTS\tEXIT\tSTDOUT\tSTDERR\tTRUNCATED")
			for _, g := range summary.Groups {
				exit := "-"
				if g.ExitCode != nil {
					exit = strconv.FormatInt(int64(*g.ExitCode), 10)
				}
				fmt.Fprintf(w, "%s (%d)\t%s\t%q\t%q\t%t\n", terminalText(strings.Join(g.Hosts, ",")), g.HostCount, exit, g.Stdout, g.Stderr, g.Truncated)
			}
		}
		if summary.Grouping != "" || summary.OmittedGroups > 0 || summary.OmittedHosts > 0 || summary.FoldedNormalHosts > 0 || summary.UnfinishedHostsCount > 0 || len(summary.OfflineHosts) > 0 {
			var parts []string
			if summary.Grouping != "" {
				parts = append(parts, "grouping="+summary.Grouping)
			}
			if summary.Ranking != "" {
				parts = append(parts, "ranking="+summary.Ranking)
			}
			if summary.TotalGroups > 0 {
				parts = append(parts, fmt.Sprintf("total_groups=%d", summary.TotalGroups))
			}
			if summary.OmittedGroups > 0 {
				parts = append(parts, fmt.Sprintf("omitted_groups=%d", summary.OmittedGroups))
			}
			if summary.OmittedHosts > 0 {
				parts = append(parts, fmt.Sprintf("omitted_hosts=%d", summary.OmittedHosts))
			}
			if summary.FoldedNormalHosts > 0 {
				parts = append(parts, fmt.Sprintf("folded_normal=%d", summary.FoldedNormalHosts))
			}
			if summary.UnfinishedHostsCount > 0 {
				parts = append(parts, fmt.Sprintf("unfinished=%d", summary.UnfinishedHostsCount))
			}
			if len(summary.OfflineHosts) > 0 {
				parts = append(parts, "offline="+strings.Join(summary.OfflineHosts, ","))
			}
			fmt.Fprintln(w, terminalText(strings.Join(parts, " ")))
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if a := j.GetApproval(); a != nil {
		_, err := fmt.Fprintf(c.OutOrStdout(), "approval_id: %s\napproval_status: %s\nexpires_at: %s\nconsole_url: %s\n",
			terminalText(a.ApprovalId), approvalStatus(a.Status), cliTimestamp(a.ExpiresAt), terminalText(a.ConsoleUrl))
		return err
	}
	return nil
}

func formatMetricValue(v float64, unit string) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if unit != "" {
		return s + unit
	}
	return s
}

func formatExitStatus(status v1.TaskStatus, code *int32) string {
	name := cliTaskStatus(status)
	if code == nil {
		return name
	}
	return fmt.Sprintf("%s(exit=%d)", name, *code)
}

func printJobDiff(c *cobra.Command, resp *v1.DiffJobsResponse) error {
	diff := resp.GetDiff()
	base := resp.GetBaseJob()
	target := resp.GetTargetJob()
	w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "BASE\tTARGET\tACTION\tGROUPING\tUNCHANGED\tADDED\tREMOVED\tREPLACED\tTRUNCATED")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%t\n",
		base.GetJobId(), target.GetJobId(), target.GetAction(), diff.GetGrouping(),
		diff.GetUnchangedHostsCount(), diff.GetAddedHostsCount(), diff.GetRemovedHostsCount(), diff.GetReplacedHostsCount(), diff.GetTruncated(),
	)
	if err := w.Flush(); err != nil {
		return err
	}
	out := c.OutOrStdout()
	if diff.GetActionDefinitionChanged() {
		fmt.Fprintln(out, "Note: action definition digest changed between base and target jobs.")
	}
	if diff.GetPreviewTruncated() {
		fmt.Fprintln(out, "Note: some host output previews were truncated at 4 KiB; use `allowops jobs output` for complete host output.")
	}
	if len(diff.GetAddedHosts()) > 0 || len(diff.GetRemovedHosts()) > 0 || len(diff.GetReplacedHosts()) > 0 {
		fmt.Fprintln(out, "\nHOST SET CHANGES")
		if len(diff.AddedHosts) > 0 {
			fmt.Fprintf(out, "  added (%d): %s\n", diff.AddedHostsCount, strings.Join(diff.AddedHosts, ", "))
		}
		if len(diff.RemovedHosts) > 0 {
			fmt.Fprintf(out, "  removed (%d): %s\n", diff.RemovedHostsCount, strings.Join(diff.RemovedHosts, ", "))
		}
		if len(diff.ReplacedHosts) > 0 {
			fmt.Fprintf(out, "  replaced (%d): %s\n", diff.ReplacedHostsCount, strings.Join(diff.ReplacedHosts, ", "))
		}
	}
	if len(diff.GetStatusTransitions()) > 0 {
		fmt.Fprintln(out, "\nSTATUS TRANSITIONS")
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "FROM\tTO\tHOSTS\tDEGRADATION\tREASON")
		for _, st := range diff.StatusTransitions {
			reason := st.Reason
			if reason == "" {
				reason = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s (%d)\t%t\t%s\n",
				formatExitStatus(st.FromStatus, st.FromExitCode),
				formatExitStatus(st.ToStatus, st.ToExitCode),
				strings.Join(st.Hosts, ","), st.HostCount, st.Degradation, reason,
			)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(diff.GetPatternChanges()) > 0 || diff.GetOmittedPatternChanges() > 0 {
		fmt.Fprintln(out, "\nPATTERN CHANGES")
		for i, pc := range diff.PatternChanges {
			tag := ""
			if pc.Unchanged {
				tag = " [unchanged]"
			}
			fmt.Fprintf(out, "  #%d %s -> %s (%d hosts: %s)%s\n",
				i+1, cliGroupSeverity(pc.BaseSeverity), cliGroupSeverity(pc.TargetSeverity),
				pc.HostCount, strings.Join(pc.Hosts, ","), tag,
			)
			for _, line := range pc.RemovedLines {
				fmt.Fprintf(out, "    - %q\n", line)
			}
			for _, line := range pc.AddedLines {
				fmt.Fprintf(out, "    + %q\n", line)
			}
			if !pc.DiffComputed && (pc.BasePreview != "" || pc.TargetPreview != "") {
				fmt.Fprintf(out, "    base:   %q\n", pc.BasePreview)
				fmt.Fprintf(out, "    target: %q\n", pc.TargetPreview)
			}
		}
		if diff.GetOmittedPatternChanges() > 0 {
			fmt.Fprintf(out, "  (%d additional pattern changes omitted due to response budget)\n", diff.OmittedPatternChanges)
		}
	}
	if len(diff.GetMetricDrifts()) > 0 {
		fmt.Fprintln(out, "\nMETRIC DRIFTS (untrusted host-derived labels)")
		dw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(dw, "METRIC\tBASE P50\tTARGET P50\tMAX DELTA\tMAX HOST\tAFFECTED")
		for _, d := range diff.MetricDrifts {
			delta := formatMetricValue(d.MaxDelta, d.Unit)
			if d.MaxDelta > 0 {
				delta = "+" + delta
			}
			if d.MaxDeltaPct != nil {
				delta = fmt.Sprintf("%s (%+.1f%%)", delta, *d.MaxDeltaPct)
			}
			fmt.Fprintf(dw, "%s\t%s\t%s\t%s\t%s\t%d/%d\n",
				d.Label,
				formatMetricValue(d.BaseP50, d.Unit),
				formatMetricValue(d.TargetP50, d.Unit),
				delta,
				d.MaxHost,
				d.AffectedHosts, d.HostCount,
			)
		}
		if err := dw.Flush(); err != nil {
			return err
		}
	}
	return nil
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
	var selector, reason, responseFormat, grouping string
	var evidenceSummary, clientRequestID string
	var names, raw, evidenceJobs []string
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
		if err := validateCLIGrouping(grouping); err != nil {
			return err
		}
		jobs, catalogs, err := jobClients()
		if err != nil {
			return err
		}
		r := &v1.RunJobRequest{Action: args[0], Reason: reason, ResponseFormat: responseFormat, Grouping: grouping, Params: &v1.Parameters{Json: []byte("{}")}, Targets: &v1.HostTargets{}}
		r.ClientRequestId = clientRequestID
		if c.Flags().Changed("evidence-job") || c.Flags().Changed("evidence-summary") {
			r.Evidence = &v1.JobEvidence{JobIds: evidenceJobs, Summary: evidenceSummary}
		}
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
			return fmt.Errorf("job %s completed with status %s", terminalText(job.GetJobId()), status)
		case v1.JobStatus_JOB_STATUS_PENDING_APPROVAL:
			a := job.GetApproval()
			_, err = fmt.Fprintf(c.ErrOrStderr(), "Job %s is pending approval (approval_id: %s, console_url: %s).\n",
				terminalText(job.GetJobId()), terminalText(a.GetApprovalId()), terminalText(a.GetConsoleUrl()))
			return err
		case v1.JobStatus_JOB_STATUS_QUEUED, v1.JobStatus_JOB_STATUS_RUNNING:
			_, err = fmt.Fprintf(c.ErrOrStderr(), "Job %s has not completed (status: %s).\n", terminalText(job.GetJobId()), status)
			return err
		default:
			// UNSPECIFIED, statuses newer than this CLI and a response without a Job.
			return fmt.Errorf("job %s has unknown status: %s", terminalText(job.GetJobId()), status)
		}
	}}
	c.Flags().StringVar(&selector, "selector", "", "Comma-separated key=value conjunctions")
	c.Flags().StringSliceVar(&names, "hosts", nil, "Explicit hostnames")
	c.Flags().Uint64Var(&expected, "expected-count", 0, "Required selector match count")
	c.Flags().StringArrayVar(&raw, "param", nil, "Action parameter name=value (arrays use JSON)")
	c.Flags().StringVar(&reason, "reason", "", "Required audit reason")
	c.Flags().StringArrayVar(&evidenceJobs, "evidence-job", nil, "Evidence job ID (repeatable)")
	c.Flags().StringVar(&evidenceSummary, "evidence-summary", "", "Evidence summary for approvers")
	c.Flags().StringVar(&clientRequestID, "client-request-id", "", "Idempotency key for an approval submission")
	c.Flags().Uint32Var(&wait, "wait-seconds", 30, "Response wait; 0 returns immediately")
	c.Flags().Uint32Var(&batch, "batch-size", 20, "Tighten the signed/default batch size")
	c.Flags().Uint32Var(&failures, "max-failures", 5, "Tighten the signed/default failure threshold")
	c.Flags().StringVar(&responseFormat, "response-format", "concise", "concise or detailed")
	c.Flags().StringVar(&grouping, "grouping", "exact", "exact or normalized")
	c.Flags().BoolVar(&jsonOutput, "json", false, "Print JSON")
	return c
}

func NewJobsCmd() *cobra.Command {
	var jsonOutput bool
	root := &cobra.Command{Use: "jobs", Short: "List, inspect, diff, read output or cancel jobs", SilenceUsage: true}
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
	var responseFormat, getGrouping string
	get := &cobra.Command{Use: "get <job-id>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		if err := validateCLIGrouping(getGrouping); err != nil {
			return err
		}
		jobs, _, err := jobClients()
		if err != nil {
			return err
		}
		r, err := jobs.GetJob(c.Context(), connect.NewRequest(&v1.GetJobRequest{JobId: args[0], WaitSeconds: &wait, ResponseFormat: responseFormat, Grouping: getGrouping}))
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
	get.Flags().StringVar(&getGrouping, "grouping", "exact", "exact or normalized")
	var diffGrouping string
	var onlyChanged bool
	diff := &cobra.Command{Use: "diff <base-job-id> <target-job-id>", Short: "Compare two finished jobs of the same action", Args: cobra.ExactArgs(2), RunE: func(c *cobra.Command, args []string) error {
		if err := validateCLIGrouping(diffGrouping); err != nil {
			return err
		}
		jobs, _, err := jobClients()
		if err != nil {
			return err
		}
		r, err := jobs.DiffJobs(c.Context(), connect.NewRequest(&v1.DiffJobsRequest{
			BaseJobId:   args[0],
			TargetJobId: args[1],
			Grouping:    diffGrouping,
			OnlyChanged: &onlyChanged,
		}))
		if err != nil {
			return jobError(err)
		}
		if jsonOutput {
			return printJobJSON(c, r.Msg)
		}
		return printJobDiff(c, r.Msg)
	}}
	diff.Flags().StringVar(&diffGrouping, "grouping", "normalized", "normalized or exact")
	diff.Flags().BoolVar(&onlyChanged, "only-changed", true, "Show only changed output patterns")
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
	root.AddCommand(list, get, diff, out, cancel)
	return root
}
