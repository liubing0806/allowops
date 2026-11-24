package output_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"gopkg.in/yaml.v3"
)

type s3HTTPClient func(*http.Request) (*http.Response, error)

func (c s3HTTPClient) Do(r *http.Request) (*http.Response, error) { return c(r) }

func newS3WithHTTPClient(t *testing.T, configYAML string, client s3HTTPClient) *output.S3 {
	t.Helper()
	var cfg output.Config
	decoder := yaml.NewDecoder(strings.NewReader("bucket: fixture\nregion: us-east-1\n" + configYAML))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "fixture-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-secret-key")
	t.Setenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
	storage, err := output.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	storage.Client = s3.New(storage.Client.Options(), func(opts *s3.Options) {
		opts.HTTPClient = client
	})
	return storage
}

func TestS3OutputConfiguration(t *testing.T) {
	const customEndpoint = "endpoint: https://s3.example.test\n"
	for _, tt := range []struct {
		name, config, host, path, sse string
	}{
		{"AWS defaults", "", "fixture.s3.us-east-1.amazonaws.com", "/example", "AES256"},
		{"custom endpoint defaults", customEndpoint, "s3.example.test", "/fixture/example", "AES256"},
		{"custom virtual-hosted endpoint", customEndpoint + "use_path_style: false\n", "fixture.s3.example.test", "/example", "AES256"},
		{"AWS path-style override", "use_path_style: true\n", "s3.us-east-1.amazonaws.com", "/fixture/example", "AES256"},
		{"empty encryption setting", customEndpoint + "server_side_encryption: \"\"\n", "s3.example.test", "/fixture/example", "AES256"},
		{"explicit AES256", customEndpoint + "server_side_encryption: AES256\n", "s3.example.test", "/fixture/example", "AES256"},
		{"use bucket encryption policy", customEndpoint + "server_side_encryption: none\n", "s3.example.test", "/fixture/example", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			storage := newS3WithHTTPClient(t, tt.config, func(r *http.Request) (*http.Response, error) {
				defer r.Body.Close()
				if r.Method != http.MethodPut || r.URL.Host != tt.host || r.URL.Path != tt.path {
					t.Errorf("request = %s %s%s, want PUT %s%s", r.Method, r.URL.Host, r.URL.Path, tt.host, tt.path)
				}
				if got := r.Header.Values("X-Amz-Server-Side-Encryption"); (tt.sse == "" && len(got) != 0) ||
					(tt.sse != "" && (len(got) != 1 || got[0] != tt.sse)) {
					t.Errorf("SSE header = %q, want %q", got, tt.sse)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			})
			if err := storage.Put(t.Context(), "example", []byte("output")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestS3RejectsInvalidEncryption(t *testing.T) {
	var cfg output.Config
	if err := yaml.Unmarshal([]byte("bucket: fixture\nregion: us-east-1\nserver_side_encryption: aws:kms\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := output.New(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "server_side_encryption") {
		t.Fatalf("invalid server_side_encryption error = %v", err)
	}
}

func TestS3ProbeLogsSanitizedFailure(t *testing.T) {
	const privateDetail = "fixture-sensitive-detail"
	for _, tt := range []struct {
		name, body   string
		transportErr error
		wantFields   []string
	}{
		{"HTTP status only", "", nil, []string{`"http_status":403`, `"s3_error_code":"Forbidden"`}},
		{"S3 API error", "<Error><Code>AccessDenied</Code><Message>" + privateDetail + "</Message></Error>", nil, []string{`"http_status":403`, `"s3_error_code":"AccessDenied"`}},
		{"unrecognized S3 code", "<Error><Code>" + privateDetail + "</Code></Error>", nil, []string{`"http_status":403`, `"s3_error_code":"Unknown"`}},
		{"transport error", "", errors.New(privateDetail), []string{`"error_type":"*http.RequestSendError"`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs strings.Builder
			original := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(original) })

			storage := newS3WithHTTPClient(t, "", func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodHead {
					t.Errorf("probe method = %s, want HEAD", r.Method)
				}
				if tt.transportErr != nil {
					return nil, tt.transportErr
				}
				return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(tt.body))}, nil
			})
			err := storage.Check(t.Context())
			if err == nil || err.Error() != "output storage unavailable" || errors.Unwrap(err) != nil {
				t.Errorf("probe error = %v, want sanitized error", err)
			}
			for _, field := range append(tt.wantFields, `"level":"ERROR"`) {
				if !strings.Contains(logs.String(), field) {
					t.Errorf("probe log = %q, missing %s", logs.String(), field)
				}
			}
			if strings.Contains(logs.String(), privateDetail) {
				t.Error("probe log includes sensitive error data")
			}
			if tt.transportErr != nil && strings.Contains(logs.String(), `"http_status"`) {
				t.Error("probe log includes an HTTP status for an error without a response")
			}
		})
	}
}
