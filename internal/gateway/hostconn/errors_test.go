package hostconn

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
)

func TestRPCErrorDetails(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{{store.ErrHostname, "HOSTNAME_EXISTS"}, {store.ErrCredential, "INVALID_CREDENTIAL"}, {store.ErrCapacity, "LIMIT_EXCEEDED"}} {
		var rpc *connect.Error
		if !errors.As(rpcError(tc.err), &rpc) {
			t.Fatal("missing Connect error")
		}
		if len(rpc.Details()) != 1 {
			t.Fatalf("details=%d, want 1 for %s", len(rpc.Details()), tc.reason)
		}
		value, err := rpc.Details()[0].Value()
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := value.(*v1.ErrorDetail); !ok || d.Reason != tc.reason {
			t.Fatalf("detail=%v, want %s", value, tc.reason)
		}
	}
}
