package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/liubing0806/allowops/internal/store"
)

func ensurePartitions(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("ensure-partitions", flag.ContinueOnError)
	// Flag parsing errors can echo supplied values.
	flags.SetOutput(io.Discard)
	months := flags.Int("months", 3, "Number of UTC months including the current month")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("usage: allowops-gateway ensure-partitions [--months 3]")
	}
	if *months < 1 || *months > 120 {
		return errors.New("--months must be between 1 and 120")
	}
	dsn := os.Getenv("ALLOWOPS_DATABASE_URL")
	if dsn == "" {
		return errors.New("ALLOWOPS_DATABASE_URL required")
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	tasks, err := db.EnsurePartitions(ctx, *months)
	if err != nil {
		return err
	}
	tables := "audit_events"
	if tasks {
		tables += " and tasks"
	}
	fmt.Printf("ensured partitions for %d UTC months in %s\n", *months, tables)
	return nil
}
