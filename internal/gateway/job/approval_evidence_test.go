package job

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func TestValidateApprovalEvidenceSummaryOnly(t *testing.T) {
	svc := &Service{}

	got, err := svc.validateApprovalEvidence(context.Background(), &v1.RunJobRequest{
		Evidence: &v1.JobEvidence{
			Summary: "Checked metrics and token=aops_sa_secret1234567890abcdef before restarting",
		},
	})
	if err != nil {
		t.Fatalf("summary-only evidence should succeed: %v", err)
	}
	if got == nil || len(got.JobIds) != 0 || !strings.Contains(got.Summary, "Checked metrics") {
		t.Fatalf("unexpected evidence=%v", got)
	}
	if strings.Contains(got.Summary, "aops_sa_secret1234567890abcdef") {
		t.Fatalf("expected summary secret redaction, got %q", got.Summary)
	}

	_, err = svc.validateApprovalEvidence(context.Background(), &v1.RunJobRequest{
		Evidence: &v1.JobEvidence{Summary: "   \t\n  "},
	})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("empty evidence err=%v, want InvalidArgument", err)
	}

	if !evidenceJobIDPattern.MatchString("job-20261124-1") || !evidenceJobIDPattern.MatchString("job-20261124-0001") {
		t.Fatalf("expected valid job IDs to match evidenceJobIDPattern")
	}
}
