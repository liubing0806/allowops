package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/store"
	"github.com/spf13/cobra"
)

// NewAuditCmd reads local files or a database selected through the existing
// ALLOWOPS_DATABASE_URL environment variable; credentials never enter argv.
func NewAuditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Export and verify the audit hash chain", SilenceUsage: true, SilenceErrors: true}
	var fromText, toText, output string
	export := &cobra.Command{Use: "export", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		parse := func(text string) (*time.Time, error) {
			if text == "" {
				return nil, nil
			}
			t, err := time.Parse(time.RFC3339Nano, text)
			return &t, err
		}
		from, err := parse(fromText)
		if err != nil {
			return fmt.Errorf("invalid --from time")
		}
		to, err := parse(toText)
		if err != nil {
			return fmt.Errorf("invalid --to time")
		}
		if from != nil && to != nil && !from.Before(*to) {
			return fmt.Errorf("--from must precede --to")
		}
		db, err := auditDB(c.Context())
		if err != nil {
			return err
		}
		defer db.Close()
		a := audit.New(db.Pool, audit.Config{})
		first, last, err := a.Bounds(c.Context(), from, to)
		if err != nil {
			return fmt.Errorf("audit range unavailable")
		}
		// Stage the full export before publishing it. A failed page cannot replace
		// an existing complete export with a misleading partial file.
		dir := ""
		if output != "" && output != "-" {
			dir = filepath.Dir(output)
		}
		file, err := os.CreateTemp(dir, ".allowops-audit-*")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		defer file.Close()
		for next := first; next != 0 && next <= last; {
			page, err := a.ExportPage(c.Context(), next, last, 0)
			if err != nil {
				return fmt.Errorf("audit export failed: %w", exportError(err))
			}
			if _, err := file.Write(page.JSONLines); err != nil {
				return err
			}
			next = page.LastSeq + 1
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if output != "" && output != "-" {
			if err := file.Close(); err != nil {
				return err
			}
			return os.Rename(file.Name(), output)
		}
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		_, err = file.WriteTo(c.OutOrStdout())
		return err
	}}
	export.Flags().StringVar(&fromText, "from", "", "Inclusive RFC3339 time")
	export.Flags().StringVar(&toText, "to", "", "Exclusive RFC3339 time")
	export.Flags().StringVarP(&output, "output", "o", "-", "JSON Lines file, or - for stdout")
	var fileName, preceding, final string
	var fromSeq, toSeq uint64
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		decode := func(s string) ([]byte, error) {
			if s == "" {
				return nil, nil
			}
			b, err := hex.DecodeString(s)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("external hash must contain 64 hexadecimal characters")
			}
			return b, nil
		}
		before, err := decode(preceding)
		if err != nil {
			return err
		}
		after, err := decode(final)
		if err != nil {
			return err
		}
		o := audit.VerifyOptions{From: fromSeq, To: toSeq, ExpectedPrecedingHash: before, ExpectedFinalHash: after}
		var v audit.Verification
		if fileName != "" {
			if fileName == "-" {
				v, err = audit.VerifyReader(c.InOrStdin(), o, audit.Config{})
			} else {
				f, e := os.Open(fileName)
				if e != nil {
					return e
				}
				defer f.Close()
				v, err = audit.VerifyReader(f, o, audit.Config{})
			}
		} else {
			db, e := auditDB(c.Context())
			if e != nil {
				return e
			}
			defer db.Close()
			v, err = audit.New(db.Pool, audit.Config{}).Verify(c.Context(), o)
		}
		if err != nil {
			return fmt.Errorf("audit verification failed: %w", exportError(err))
		}
		if err := json.NewEncoder(c.OutOrStdout()).Encode(v); err != nil {
			return err
		}
		if !v.Valid {
			return fmt.Errorf("audit chain invalid at seq %d: %s", *v.FirstInvalidSeq, v.Reason)
		}
		return nil
	}}
	verify.Flags().StringVar(&fileName, "file", "", "Verify JSON Lines instead of PostgreSQL (- for stdin)")
	verify.Flags().Uint64Var(&fromSeq, "from-seq", 0, "First sequence (inclusive)")
	verify.Flags().Uint64Var(&toSeq, "to-seq", 0, "Last sequence (inclusive)")
	verify.Flags().StringVar(&preceding, "expected-preceding-hash", "", "External preceding SHA-256 in hex")
	verify.Flags().StringVar(&final, "expected-final-hash", "", "External final SHA-256 in hex")
	_ = verify.MarkFlagRequired("from-seq")
	_ = verify.MarkFlagRequired("to-seq")
	cmd.AddCommand(export, verify)
	return cmd
}

func auditDB(ctx context.Context) (*store.Store, error) {
	dsn := os.Getenv("ALLOWOPS_DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("ALLOWOPS_DATABASE_URL required")
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.CheckSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func exportError(err error) error {
	for _, known := range []error{audit.ErrInvalid, audit.ErrLimit, audit.ErrUnavailable} {
		if errors.Is(err, known) {
			return known
		}
	}
	return fmt.Errorf("database operation failed")
}
