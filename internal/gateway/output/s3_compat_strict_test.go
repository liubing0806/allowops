package output_test

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/liubing0806/allowops/internal/gateway/output"
)

// Each provider must accept a gateway write when configured for its compatibility mode.
func TestS3StrictCompatibility(t *testing.T) {
	falseVal := false
	for _, tc := range []struct {
		name      string
		options   s3ProviderOptions
		configure func(*output.Config)
	}{
		{
			name:    "NoSSEProvider",
			options: s3ProviderOptions{rejectSSE: true},
			configure: func(c *output.Config) {
				c.ServerSideEncryption = "none"
			},
		},
		{
			name:    "VirtualHostedOnlyProvider",
			options: s3ProviderOptions{virtualHostedOnly: true},
			configure: func(c *output.Config) {
				c.UsePathStyle = &falseVal
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := s3ContractConfig()
			tc.configure(&cfg)
			provider, store := newS3Provider(t, cfg, tc.options)
			const key = "output.zst"
			writeErr := store.Put(t.Context(), key, []byte("output"))
			requests := provider.history()
			if len(requests) != 1 || requests[0].method != "PUT" {
				t.Fatalf("expected one gateway PUT, got %d requests", len(requests))
			}
			got := requests[0]
			// Send the same key and compressed bytes. Change only the option
			// required by this provider, using the original client's signer.
			probe := &s3.PutObjectInput{
				Bucket: aws.String(s3Bucket), Key: aws.String(key),
				Body: bytes.NewReader(got.body), ContentType: aws.String(got.header.Get("Content-Type")),
			}
			if !tc.options.rejectSSE {
				probe.ServerSideEncryption = types.ServerSideEncryption(got.header.Get(sseHeader))
			}
			_, controlErr := store.Client.PutObject(t.Context(), probe, func(o *s3.Options) {
				if tc.options.virtualHostedOnly {
					o.UsePathStyle = false
				}
			})
			requests = provider.history()
			if len(requests) != 2 {
				t.Fatalf("expected one gateway PUT and one SDK control, got %d requests", len(requests))
			}
			control := requests[1]
			if controlErr != nil || control.method != "PUT" || control.response.status != http.StatusOK {
				t.Fatalf("SDK control %s %s%s returned %d %s, want successful PUT",
					control.method, control.host, control.path, control.response.status, control.response.code)
			}
			if writeErr != nil {
				requireStorageError(t, writeErr)
				t.Fatalf("PUT %s%s SSE=%q -> %d %s (%v). Control %s%s SSE=%q -> %d",
					got.host, got.path, got.header.Get(sseHeader), got.response.status, got.response.code, writeErr,
					control.host, control.path, control.header.Get(sseHeader), control.response.status)
			}
			if got.response.status != http.StatusOK || got.host != control.host || got.path != control.path {
				t.Fatalf("gateway PUT %s%s returned %d, want 200 at %s%s", got.host, got.path, got.response.status, control.host, control.path)
			}
		})
	}
}
