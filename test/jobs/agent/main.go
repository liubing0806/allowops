// This fixture runs the unchanged host agent as allowops inside a local container (design P3).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/liubing0806/allowops/internal/agent"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "local agent fixture failed:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := agent.CheckCommandUser(false); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var input struct{ Upstream, Pin, Token, Hostname string }
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 64<<10)).Decode(&input); err != nil {
		return fmt.Errorf("invalid fixture input")
	}
	c := agent.Config{Upstream: input.Upstream, CAPin: input.Pin}
	if _, err := agent.Join(ctx, c, input.Token, input.Hostname, agent.DataDirectory); err != nil {
		return err
	}
	a, err := agent.New(c, agent.Options{Version: "0.1.0", KeyOwner: 0})
	if err != nil {
		return err
	}
	fmt.Println("local P3 agent joined as allowops")
	err = a.Run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return err
}
