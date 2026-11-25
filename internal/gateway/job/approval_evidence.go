package job

import (
	"context"
	"regexp"
	"strings"
	"unicode/utf8"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/gateway/reqctx"
	"github.com/liubing0806/allowops/internal/redact"
)

var (
	clientRequestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
	evidenceJobIDPattern   = regexp.MustCompile(`^job-[0-9]{8}-[0-9]{1,20}$`)
)

func validApprovalText(text string) bool {
	return len(text) <= 4096 && utf8.ValidString(text) && utf8.RuneCountInString(text) <= 1024 && !strings.ContainsRune(text, 0)
}

func (s *Service) validateApprovalEvidence(ctx context.Context, r *v1.RunJobRequest) (*v1.JobEvidence, error) {
	if r.ClientRequestId != "" && !clientRequestIDPattern.MatchString(r.ClientRequestId) {
		return nil, failure(connect.CodeInvalidArgument, "INVALID_CLIENT_REQUEST_ID")
	}
	evidence := r.Evidence
	if evidence == nil {
		return nil, nil
	}
	if (len(evidence.JobIds) == 0 && strings.TrimSpace(evidence.Summary) == "") || len(evidence.JobIds) > 5 || !validApprovalText(evidence.Summary) {
		return nil, failure(connect.CodeInvalidArgument, "INVALID_EVIDENCE")
	}
	evidenceCtx := context.WithValue(reqctx.ForkRequestContext(ctx), operationKey{}, &operationState{})
	seen := map[string]bool{}
	for _, id := range evidence.JobIds {
		if !evidenceJobIDPattern.MatchString(id) || seen[id] {
			return nil, failure(connect.CodeInvalidArgument, "INVALID_EVIDENCE_JOB")
		}
		seen[id] = true
		j, err := s.get(evidenceCtx, id)
		if err == nil {
			_, _, err = s.authorize(evidenceCtx, j, authz.ViewJobs, false, "")
		}
		if err != nil {
			switch connect.CodeOf(err) {
			case connect.CodeNotFound, connect.CodePermissionDenied:
				return nil, failure(connect.CodeInvalidArgument, "INVALID_EVIDENCE_JOB")
			case connect.CodeUnknown:
				return nil, failure(connect.CodeUnavailable, "JOB_DATABASE_UNAVAILABLE")
			default:
				return nil, err
			}
		}
	}
	redactor, err := redact.New(nil)
	if err != nil {
		return nil, err
	}
	var summary strings.Builder
	if err := redactor.Stream(strings.NewReader(evidence.Summary), &summary, 4096); err != nil {
		return nil, err
	}
	return &v1.JobEvidence{JobIds: evidence.JobIds, Summary: summary.String()}, nil
}
