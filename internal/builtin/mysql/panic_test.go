package mysql

import (
	"context"
	"errors"
	"testing"

	"github.com/pingcap/tidb/pkg/parser/ast"
)

// This number is the minimized FuzzValidateSQL/17f3b73fe43e0cf0 input.
const parserPanicNumber = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000"

func TestParserPanicRejected(t *testing.T) {
	for _, sql := range []string{parserPanicNumber, "SELECT " + parserPanicNumber} {
		t.Run(sql, func(t *testing.T) {
			if err := validateSQL(sql); !errors.Is(err, errSQL) {
				t.Fatalf("got %v; want SQL rejection", err)
			}
			result, err := Run(context.Background(), Config{Credential: "/missing/panic-test.json", Address: "tcp://127.0.0.1:1"}, Params{Database: "fixture", SQL: sql})
			if !errors.Is(err, errSQL) || result != (Result{}) {
				t.Fatalf("panic input must be rejected before credential IO: result=%+v err=%v", result, err)
			}
		})
	}
	if err := validateSQL("SELECT 1"); err != nil {
		t.Fatalf("valid query after panic rejection: %v", err)
	}
}

func TestParserConstructorPanicRejected(t *testing.T) {
	original := ast.NewValueExpr
	defer func() { ast.NewValueExpr = original }()
	// Legacy panic(nil) must also be rejected, even though recover returns nil.
	t.Setenv("GODEBUG", "panicnil=1")
	for _, value := range []any{"SQL password=must-not-leak", nil} {
		ast.NewValueExpr = func(any, string, string) ast.ValueExpr { panic(value) }
		if err := validateSQL("SELECT 1"); err != errSQL {
			t.Errorf("got %v; want fixed SQL rejection", err)
		}
	}
}
