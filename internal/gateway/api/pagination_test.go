package api

import (
	"connectrpc.com/connect"
	"context"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestPageStopsAtEncodedByteBudget(t *testing.T) {
	cfg := Config{PageSize: 50, MaxPageSize: 200}
	if err := yaml.Unmarshal([]byte("message_bytes: 400"), &cfg); err != nil {
		t.Fatal(err)
	}
	items := []*v1.User{{UserId: "a", DisplayName: strings.Repeat("x", 200)}, {UserId: "b", DisplayName: strings.Repeat("x", 200)}}
	first, cursor, err := page(context.Background(), cfg, "users", nil, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || cursor.NextPageToken == "" {
		t.Fatalf("byte-limited page items=%d cursor=%t; want 1 and continuation", len(first), cursor.NextPageToken != "")
	}
	next, final, err := page(context.Background(), cfg, "users", &v1.PageRequest{PageToken: cursor.NextPageToken}, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 1 || next[0].UserId != "b" || final.NextPageToken != "" {
		t.Fatal("pagination lost or repeated an item")
	}
	_, _, err = page(context.Background(), cfg, "users", nil, []*v1.User{{DisplayName: strings.Repeat("x", 1000)}})
	code(t, err, connect.CodeResourceExhausted)
}
