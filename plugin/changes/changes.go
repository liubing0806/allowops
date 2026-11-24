// Package changes defines the experimental change history extension point.
package changes

import (
	"context"
	"time"
)

type Change struct {
	At      time.Time
	Kind    string
	Service string
	Summary string
	Actor   string
	Ref     string
}

// Query requests up to MaxItems changes in the inclusive UTC window.
type Query struct {
	From     time.Time
	To       time.Time
	MaxItems int
}

type ListResult struct {
	Changes []Change
	HasMore bool
}

type Lister interface {
	List(ctx context.Context, q Query) (ListResult, error)
}
