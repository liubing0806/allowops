// Package inventory defines the experimental inventory extension point.
package inventory

import "context"

type Entity struct {
	Kind     string
	Name     string
	Attrs    map[string]string
	Hosts    []string
	Selector string
	// DependsOn refers to kind/name within the same plugin instance.
	DependsOn []string
}

type Query struct {
	Kind string
	Name string
}

type Resolver interface {
	// Resolve returns all matching entities. The caller owns the returned maps
	// and slices; the plugin must not modify them after returning.
	Resolve(ctx context.Context, q Query) ([]Entity, error)
}
