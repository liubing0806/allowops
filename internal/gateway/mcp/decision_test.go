package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
)

func TestA27EmptyHostSearchAllowed(t *testing.T) {
	if err := validateHostSearchSelection("", ""); err != nil {
		t.Fatalf("A27 empty search rejected: %v", err)
	}
}
func TestG54DenialDetailsKeepPrefixAndTotalWithinBudget(t *testing.T) {
	denied := make([]*v1.HostDenial, 500)
	for i := range denied {
		denied[i] = &v1.HostDenial{Host: fmt.Sprintf("host-%04d", i), Rules: []string{strings.Repeat("rule", 60)}}
	}
	detail, err := connect.NewErrorDetail(&v1.ErrorDetail{Reason: "JOB_DENIED", DeniedHosts: denied})
	if err != nil {
		t.Fatal(err)
	}
	deniedError := connect.NewError(connect.CodePermissionDenied, errors.New("job denied"))
	deniedError.AddDetail(detail)
	result := toolError(deniedError, &callState{})
	data, _ := json.Marshal(result)
	if len(data) > resultByteLimit {
		t.Fatalf("error result bytes=%d", len(data))
	}
	content := result.StructuredContent.(map[string]any)
	if content["denied_count"] != 500 || content["details_truncated"] != true {
		t.Fatalf("total/truncation=%v", content)
	}
	kept, ok := content["denied_hosts"].([]*v1.HostDenial)
	if !ok || len(kept) == 0 || len(kept) >= len(denied) || kept[0].Host != "host-0000" {
		t.Fatalf("denied prefix=%v", content["denied_hosts"])
	}
	for i, host := range kept {
		if host.Host != denied[i].Host || len(host.Rules) != 1 {
			t.Fatalf("denial %d=%v", i, host)
		}
	}
}
