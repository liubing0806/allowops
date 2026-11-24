package cli

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	rpc "github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func approvalClient() (rpc.ApprovalServiceClient, error) {
	c, err := loadCredentials()
	if err != nil {
		return nil, err
	}
	client, err := gatewayClient(c.Gateway, c.CAFile)
	if err != nil {
		return nil, err
	}
	return rpc.NewApprovalServiceClient(client, c.Gateway, connect.WithInterceptors(bearer(c.Token))), nil
}

func NewApprovalsCmd() *cobra.Command {
	root := &cobra.Command{Use: "approvals", Short: "List, inspect and decide job approvals", SilenceUsage: true}
	var jsonOutput bool
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Print JSON")

	var status string
	listRequest := &v1.ListApprovalsRequest{Page: &v1.PageRequest{}}
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if c.Flags().Changed("status") {
			s := v1.ApprovalStatus(v1.ApprovalStatus_value["APPROVAL_STATUS_"+strings.ToUpper(status)])
			if s == v1.ApprovalStatus_APPROVAL_STATUS_UNSPECIFIED || approvalStatus(s) != status {
				return fmt.Errorf("--status must be pending, approved, rejected, expired, cancelled or execution_denied")
			}
			listRequest.Statuses = []v1.ApprovalStatus{s}
		}
		client, err := approvalClient()
		if err != nil {
			return err
		}
		r, err := client.ListApprovals(c.Context(), connect.NewRequest(listRequest))
		if err != nil {
			return approvalCLIError(err)
		}
		if jsonOutput {
			return printJobJSON(c, r.Msg)
		}
		w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "APPROVAL\tJOB\tACTION\tREQUESTER\tSTATUS\tEXPIRES AT\tCAN APPROVE")
		for _, a := range r.Msg.Approvals {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%t\n",
				terminalText(a.GetApprovalId()), terminalText(a.GetJobId()), terminalText(a.GetAction()),
				terminalText(a.GetRequesterSubjectId()), approvalStatus(a.GetStatus()), cliTimestamp(a.GetExpiresAt()), a.GetCanApprove())
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if next := r.Msg.Page.GetNextPageToken(); next != "" {
			_, err = fmt.Fprintf(c.OutOrStdout(), "next_page_token: %s\n", terminalText(next))
		}
		return err
	}}
	list.Flags().StringVar(&status, "status", "", "Filter by approval status")
	list.Flags().StringVar(&listRequest.Action, "action", "", "Filter by action name")
	list.Flags().StringVar(&listRequest.RequesterSubjectId, "requester", "", "Filter by requester ID")
	list.Flags().BoolVar(&listRequest.OnlyActionable, "actionable", false, "Show approvals the caller may decide")
	list.Flags().Uint32Var(&listRequest.Page.PageSize, "page-size", 50, "Page size (maximum 200)")
	list.Flags().StringVar(&listRequest.Page.PageToken, "page-token", "", "Page cursor")

	get := &cobra.Command{Use: "get <approval-id>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		client, err := approvalClient()
		if err != nil {
			return err
		}
		r, err := client.GetApproval(c.Context(), connect.NewRequest(&v1.GetApprovalRequest{ApprovalId: args[0]}))
		if err != nil {
			return approvalCLIError(err)
		}
		if jsonOutput {
			return printJobJSON(c, r.Msg)
		}
		return printApproval(c.OutOrStdout(), r.Msg.Approval)
	}}

	var approveReason string
	var approveYes bool
	approve := &cobra.Command{Use: "approve <approval-id>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		client, err := approvalClient()
		if err != nil {
			return err
		}
		r, err := client.GetApproval(c.Context(), connect.NewRequest(&v1.GetApprovalRequest{ApprovalId: args[0]}))
		if err != nil {
			return approvalCLIError(err)
		}
		a := r.Msg.Approval
		if len(a.GetRequestDigest()) != sha256.Size {
			return fmt.Errorf("gateway approval has an invalid request digest")
		}
		planOut := c.OutOrStdout()
		if jsonOutput {
			planOut = c.ErrOrStderr()
		}
		if _, err := io.WriteString(planOut, approvalPlan(a)); err != nil {
			return err
		}
		if err := confirmApproval(c, "Approve", args[0], approveYes); err != nil {
			return err
		}
		result, err := client.ApproveRequest(c.Context(), connect.NewRequest(&v1.ApproveRequestRequest{
			ApprovalId: args[0], Reason: approveReason, ExpectedRequestDigest: a.RequestDigest,
		}))
		if err != nil {
			return approvalCLIError(err)
		}
		if jsonOutput {
			return printJobJSON(c, result.Msg)
		}
		return printApprovalStatus(c.OutOrStdout(), result.Msg.Approval)
	}}
	approve.Flags().StringVar(&approveReason, "reason", "", "Approval reason")
	approve.Flags().BoolVar(&approveYes, "yes", false, "Confirm without prompting")

	var rejectReason string
	var rejectYes bool
	reject := &cobra.Command{Use: "reject <approval-id>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		if strings.TrimSpace(rejectReason) == "" {
			return fmt.Errorf("--reason required")
		}
		if err := confirmApproval(c, "Reject", args[0], rejectYes); err != nil {
			return err
		}
		client, err := approvalClient()
		if err != nil {
			return err
		}
		r, err := client.RejectRequest(c.Context(), connect.NewRequest(&v1.RejectRequestRequest{
			ApprovalId: args[0], Reason: rejectReason,
		}))
		if err != nil {
			return approvalCLIError(err)
		}
		if jsonOutput {
			return printJobJSON(c, r.Msg)
		}
		return printApprovalStatus(c.OutOrStdout(), r.Msg.Approval)
	}}
	reject.Flags().StringVar(&rejectReason, "reason", "", "Required rejection reason")
	reject.Flags().BoolVar(&rejectYes, "yes", false, "Confirm without prompting")

	var cancelYes bool
	cancel := &cobra.Command{Use: "cancel <approval-id>", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		if err := confirmApproval(c, "Cancel", args[0], cancelYes); err != nil {
			return err
		}
		client, err := approvalClient()
		if err != nil {
			return err
		}
		r, err := client.CancelApproval(c.Context(), connect.NewRequest(&v1.CancelApprovalRequest{ApprovalId: args[0]}))
		if err != nil {
			return approvalCLIError(err)
		}
		if jsonOutput {
			return printJobJSON(c, r.Msg)
		}
		return printApprovalStatus(c.OutOrStdout(), r.Msg.Approval)
	}}
	cancel.Flags().BoolVar(&cancelYes, "yes", false, "Confirm without prompting")

	root.AddCommand(list, get, approve, reject, cancel)
	return root
}

func confirmApproval(c *cobra.Command, verb, id string, yes bool) error {
	if yes {
		return nil
	}
	input, ok := c.InOrStdin().(*os.File)
	if !ok {
		return fmt.Errorf("use --yes for non-terminal input")
	}
	if _, err := unix.IoctlGetTermios(int(input.Fd()), unix.TCGETS); err != nil {
		return fmt.Errorf("use --yes for non-terminal input")
	}
	if _, err := fmt.Fprintf(c.ErrOrStderr(), "%s approval %s? [y/N] ", verb, terminalText(id)); err != nil {
		return err
	}
	answers := make(chan string, 1)
	go func() {
		line, err := bufio.NewReader(input).ReadSlice('\n')
		if err != nil {
			answers <- ""
			return
		}
		answers <- strings.ToLower(strings.TrimSpace(string(line)))
	}()
	select {
	case <-c.Context().Done():
		return c.Context().Err()
	case answer := <-answers:
		if answer == "y" || answer == "yes" {
			return nil
		}
		return fmt.Errorf("approval operation not confirmed")
	}
}

func approvalStatus(status v1.ApprovalStatus) string {
	return strings.ToLower(strings.TrimPrefix(status.String(), "APPROVAL_STATUS_"))
}

func cliTimestamp(t *timestamppb.Timestamp) string {
	if t == nil {
		return "-"
	}
	return t.AsTime().Format(time.RFC3339Nano)
}

// Keep each field on one line and prevent terminal control sequences from being interpreted.
func terminalText(s string) string {
	var out strings.Builder
	for _, r := range s {
		if strconv.IsPrint(r) {
			out.WriteRune(r)
		} else {
			escaped := strconv.QuoteRune(r)
			out.WriteString(escaped[1 : len(escaped)-1])
		}
	}
	return out.String()
}

func approvalCLIError(err error) error {
	return fmt.Errorf("%s", terminalText(jobError(err).Error()))
}

func approvalPlan(a *v1.ApprovalRequest) string {
	var plan strings.Builder
	fmt.Fprintln(&plan, "GATEWAY-VERIFIED EXECUTION PLAN")
	fmt.Fprintf(&plan, "approval_id: %s\naction: %s\nrisk: %s\ncatalog: %s (version %d)\n",
		terminalText(a.GetApprovalId()), terminalText(a.GetAction()), terminalText(a.GetActionRisk()),
		terminalText(a.GetCatalog().GetCatalogId()), a.GetCatalog().GetVersion())
	fmt.Fprintf(&plan, "action_sha256: %x\nrequest_digest: %x\n", a.GetActionSha256(), a.GetRequestDigest())
	fmt.Fprintf(&plan, "target_selector: %s\nfrozen target hosts (%d):\n", terminalText(a.GetTargetSelector()), len(a.GetTargets()))
	for _, t := range a.GetTargets() {
		fmt.Fprintf(&plan, "  hostname: %s, host_id: %s\n", terminalText(t.GetHostname()), terminalText(t.GetHostId()))
	}
	fmt.Fprintf(&plan, "params_json: %s\nfilters_json: %s\nbatch_size: %d\nmax_failures: %d\n",
		terminalJSON(a.GetParamsJson()), terminalJSON(a.GetFiltersJson()), a.GetBatchSize(), a.GetMaxFailures())
	return plan.String()
}

func terminalJSON(raw []byte) string {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return terminalText(string(raw))
	}
	return terminalText(compact.String())
}

func printApproval(w io.Writer, a *v1.ApprovalRequest) error {
	if a == nil {
		return fmt.Errorf("gateway approval unavailable")
	}
	if _, err := io.WriteString(w, approvalPlan(a)); err != nil {
		return err
	}
	var details strings.Builder
	fmt.Fprintln(&details, "\nUNTRUSTED REQUESTER CONTEXT")
	fmt.Fprintf(&details, "requester: %s (%s)\nrequester_owner: %s\nreason: %s\n",
		terminalText(a.RequesterSubjectId), terminalText(a.RequesterKind), terminalText(a.RequesterOwnerId), terminalText(a.Reason))
	if e := a.Evidence; e != nil {
		fmt.Fprintf(&details, "evidence.summary: %s\nevidence.job_ids: %s\n",
			terminalText(e.Summary), terminalText(strings.Join(e.JobIds, ", ")))
	}
	fmt.Fprintln(&details, "\nAPPROVAL STATUS")
	fmt.Fprintf(&details, "job_id: %s\nstatus: %s\ncreated_at: %s\nexpires_at: %s\nconsole_url: %s\n",
		terminalText(a.JobId), approvalStatus(a.Status), cliTimestamp(a.CreatedAt), cliTimestamp(a.ExpiresAt), terminalText(a.ConsoleUrl))
	fmt.Fprintf(&details, "policy_version: %d\nmatched_rules: %s\napproved_count: %d\nmin_approvals: %d\nallow_owner_approve: %t\ncan_approve: %t\n",
		a.PolicyVersion, terminalText(strings.Join(a.MatchedRules, ", ")), a.ApprovedCount, a.MinApprovals, a.AllowOwnerApprove, a.CanApprove)
	if a.CannotApproveReason != "" {
		fmt.Fprintf(&details, "cannot_approve_reason: %s\n", terminalText(a.CannotApproveReason))
	}
	for _, set := range a.RequiredApproverRoleSets {
		fmt.Fprintf(&details, "required role set: %s\n", terminalText(strings.Join(set.GetRoles(), ", ")))
	}
	for _, vote := range a.Decisions {
		fmt.Fprintf(&details, "vote: %s, actor_id: %s, actor_email: %s, decided_at: %s, policy_version: %d, matched_rules: %s, reason: %s\n",
			strings.ToLower(strings.TrimPrefix(vote.GetVote().String(), "APPROVAL_VOTE_")),
			terminalText(vote.GetActorId()), terminalText(vote.GetActorEmail()), cliTimestamp(vote.GetDecidedAt()), vote.GetPolicyVersion(),
			terminalText(strings.Join(vote.GetMatchedRules(), ", ")), terminalText(vote.GetReason()))
	}
	if a.DecidedAt != nil {
		fmt.Fprintf(&details, "decided_at: %s\ndecided_by: %s\ndecision_reason: %s\n",
			cliTimestamp(a.DecidedAt), terminalText(a.DecidedBy), terminalText(a.DecisionReason))
	}
	if a.RecheckPolicyVersion != nil {
		fmt.Fprintf(&details, "recheck_policy_version: %d\n", a.GetRecheckPolicyVersion())
	}
	fmt.Fprintf(&details, "recheck_error: %s\nnotify_status: %s\nnotify_error: %s\n",
		terminalText(a.RecheckError), terminalText(a.NotifyStatus), terminalText(a.NotifyError))
	_, err := io.WriteString(w, details.String())
	return err
}

func printApprovalStatus(w io.Writer, a *v1.ApprovalRequest) error {
	_, err := fmt.Fprintf(w, "Approval %s: %s (%d/%d approved)\n",
		terminalText(a.GetApprovalId()), approvalStatus(a.GetStatus()), a.GetApprovedCount(), a.GetMinApprovals())
	return err
}
