// Package knowledge defines the experimental document extension point.
package knowledge

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("knowledge document not found")

type Doc struct {
	ID       string
	Title    string
	Summary  string
	Tags     []string
	Headings []string
}

type SearchQuery struct {
	Query   string
	Tags    []string
	MaxDocs int
}

// ReadResult contains metadata and content from the same immutable snapshot.
type ReadResult struct {
	Doc     Doc
	Content string
}

type Store interface {
	Search(ctx context.Context, q SearchQuery) ([]Doc, error)
	Read(ctx context.Context, id string) (ReadResult, error)
}
