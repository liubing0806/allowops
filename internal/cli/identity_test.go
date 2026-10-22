package cli

import (
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func TestRPCErrorReportsPossibleCommitWithoutEchoingServerSecrets(t *testing.T) {
	err := connect.NewError(connect.CodeUnavailable, errors.New("provider-password-must-not-leak"))
	detail, detailErr := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "AUDIT_RESULT_UNAVAILABLE"})
	if detailErr != nil {
		t.Fatal(detailErr)
	}
	err.AddDetail(detail)
	message := rpcError(err).Error()
	if !strings.Contains(message, "may have committed") || strings.Contains(message, "provider-password") {
		t.Fatalf("CLI audit failure message=%q", message)
	}
}
