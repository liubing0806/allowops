package output_test

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/klauspost/compress/zstd"
	"github.com/liubing0806/allowops/internal/gateway/output"
)

const (
	s3Host      = "objects.example.test"
	s3Bucket    = "contract-outputs"
	s3Region    = "us-east-1"
	s3AccessKey = "contract-access-key"
	s3SecretKey = "contract-secret-key"
	sseHeader   = "X-Amz-Server-Side-Encryption"
)

type s3Response struct {
	status int
	code   string
}

type s3ProviderOptions struct {
	rejectSSE         bool
	virtualHostedOnly bool
	failures          map[string]s3Response // HTTP method -> S3 response
}

type s3Request struct {
	method, host, path string
	header             http.Header
	body               []byte
	response           s3Response
}

// The provider serves one existing bucket. Both addressing styles refer to
// the same object map. Each exchange retains the request as seen on the wire.
type s3Provider struct {
	options s3ProviderOptions

	mu       sync.Mutex
	requests []s3Request
	objects  map[string]s3Request
}

func (p *s3Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	req := s3Request{method: r.Method, host: r.Host, path: r.URL.EscapedPath(), header: r.Header.Clone(), body: body}
	req.response.status = http.StatusOK
	p.mu.Lock()
	defer p.mu.Unlock()
	defer func() { p.requests = append(p.requests, req) }()

	// A failed SDK request can carry provider-supplied request IDs and error
	// messages. Put both synthetic credential markers in those channels.
	reject := func(status int, code string) {
		req.response = s3Response{status, code}
		w.Header().Set("X-Amz-Request-Id", s3AccessKey)
		w.Header().Set("X-Amz-Id-2", s3SecretKey)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_ = xml.NewEncoder(w).Encode(struct {
				XMLName xml.Name `xml:"Error"`
				Code    string
				Message string
			}{Code: code, Message: s3AccessKey + " " + s3SecretKey})
		}
	}
	if err != nil {
		reject(http.StatusBadRequest, "IncompleteBody")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch r.Host {
	case s3Bucket + "." + s3Host:
		// Virtual-hosted requests have only the key in the path.
	case s3Host:
		if p.options.virtualHostedOnly {
			reject(http.StatusBadRequest, "InvalidRequest")
			return
		}
		var bucket string
		bucket, key, _ = strings.Cut(key, "/")
		if bucket != s3Bucket {
			reject(http.StatusNotFound, "NoSuchBucket")
			return
		}
	default:
		reject(http.StatusNotFound, "NoSuchBucket")
		return
	}
	if failure, ok := p.options.failures[r.Method]; ok {
		reject(failure.status, failure.code)
		return
	}
	switch {
	case r.Method == http.MethodHead && key == "":
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPut && key != "":
		if _, present := r.Header[http.CanonicalHeaderKey(sseHeader)]; present && p.options.rejectSSE {
			reject(http.StatusBadRequest, "InvalidRequest")
			return
		}
		p.objects[key] = req
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && key != "":
		object, ok := p.objects[key]
		if !ok {
			reject(http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Type", object.header.Get("Content-Type"))
		_, _ = w.Write(object.body)
	default:
		reject(http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func (p *s3Provider) history() []s3Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.requests)
}

func setS3TestCredentials(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", s3AccessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", s3SecretKey)
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", os.DevNull)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", os.DevNull)
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "false")
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "false")
	t.Setenv("AWS_RETRY_MODE", "")
	t.Setenv("AWS_DEFAULTS_MODE", "")
	t.Setenv("AWS_MAX_ATTEMPTS", "1") // Observe each injected 5xx without retry backoff.
}

func s3ContractConfig() output.Config {
	return output.Config{Bucket: s3Bucket, Region: s3Region, Endpoint: "http://" + s3Host}
}

func newS3Provider(t *testing.T, cfg output.Config, options s3ProviderOptions) (*s3Provider, *output.S3) {
	t.Helper()
	setS3TestCredentials(t)
	provider := &s3Provider{options: options, objects: make(map[string]s3Request)}
	server := httptest.NewTestServer(t, provider)
	store, err := output.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Only replace the HTTP transport. httptest routes both the endpoint
	// and bucket subdomain in memory, leaving SDK addressing and signing intact.
	opts := store.Client.Options()
	opts.HTTPClient = server.Client()
	store.Client = s3.New(opts)
	return provider, store
}

func requireStorageError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected storage operation to fail")
	}
	if strings.Contains(err.Error(), s3AccessKey) || strings.Contains(err.Error(), s3SecretKey) {
		t.Fatal("storage error contains an AWS test credential")
	}
}

func TestS3ConfigurationContract(t *testing.T) {
	setS3TestCredentials(t)
	for _, tc := range []struct {
		name string
		cfg  output.Config
	}{
		{"missing bucket", output.Config{Region: s3Region}},
		{"missing region", output.Config{Bucket: s3Bucket}},
		{"endpoint scheme", output.Config{Bucket: s3Bucket, Region: s3Region, Endpoint: "ftp://" + s3Host}},
		{"endpoint userinfo", output.Config{Bucket: s3Bucket, Region: s3Region, Endpoint: "https://" + s3AccessKey + ":" + s3SecretKey + "@" + s3Host}},
		{"endpoint without host", output.Config{Bucket: s3Bucket, Region: s3Region, Endpoint: "https:///objects"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := output.New(t.Context(), tc.cfg)
			requireStorageError(t, err)
			if store != nil {
				t.Fatal("returned a store for invalid configuration")
			}
		})
	}
}

func TestS3ObjectContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"binary", []byte{0, 10, 13, 127, 128, 255}},
		{"large", bytes.Repeat([]byte("stdout\x00\xff\r\n"), 1<<18)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, store := newS3Provider(t, s3ContractConfig(), s3ProviderOptions{})
			ctx := t.Context()
			const key = "outputs/job/std out.zst"
			if err := store.Check(ctx); err != nil {
				t.Fatal(err)
			}
			if err := store.Put(ctx, key, tc.data); err != nil {
				t.Fatal(err)
			}
			got, err := store.Get(ctx, key, int64(len(tc.data)))
			if err != nil || !bytes.Equal(got, tc.data) {
				t.Fatalf("Get at exact byte limit returned %d bytes, want %d matching bytes, error=%v", len(got), len(tc.data), err)
			}
			requests := provider.history()
			if len(requests) != 3 {
				t.Fatalf("received %d requests, want HEAD, PUT, GET", len(requests))
			}
			bucketPath := "/" + s3Bucket
			objectPath := bucketPath + "/outputs/job/std%20out.zst"
			for i, want := range []struct{ method, path string }{{"HEAD", bucketPath}, {"PUT", objectPath}, {"GET", objectPath}} {
				req := requests[i]
				path := req.path
				if want.method == "HEAD" {
					path = strings.TrimSuffix(path, "/")
				}
				if req.method != want.method || req.host != s3Host || path != want.path {
					t.Fatalf("request %d: %s %s%s, want %s %s%s", i, req.method, req.host, req.path, want.method, s3Host, want.path)
				}
				auth := req.header.Get("Authorization")
				if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+s3AccessKey+"/") || !strings.Contains(auth, "/"+s3Region+"/s3/aws4_request") {
					t.Fatalf("%s missing expected SigV4 credential scope", want.method)
				}
			}
			put := requests[1]
			if put.header.Get("Content-Type") != "application/zstd" || put.header.Get(sseHeader) != "AES256" {
				t.Fatalf("PUT content type=%q, server-side encryption=%q", put.header.Get("Content-Type"), put.header.Get(sseHeader))
			}
			decoder, err := zstd.NewReader(nil)
			if err != nil {
				t.Fatal(err)
			}
			defer decoder.Close()
			// EncodeAll produces zero frames for empty input. For every
			// nonempty upload this also checks the compressed bytes independently of Get.
			plain, err := decoder.DecodeAll(put.body, nil)
			if err != nil || !bytes.Equal(plain, tc.data) {
				t.Fatalf("wire zstd decoded to %d bytes, want %d matching bytes, error=%v", len(plain), len(tc.data), err)
			}
		})
	}
}

func TestS3ProviderErrors(t *testing.T) {
	for _, tc := range []struct {
		method string
		status int
		code   string
	}{
		{"HEAD", 403, "AccessDenied"}, {"HEAD", 500, "InternalError"},
		{"PUT", 403, "AccessDenied"}, {"PUT", 500, "InternalError"}, {"PUT", 503, "ServiceUnavailable"},
		{"GET", 404, "NoSuchKey"}, {"GET", 500, "InternalError"},
	} {
		t.Run(tc.method+"/"+tc.code, func(t *testing.T) {
			failure := s3Response{tc.status, tc.code}
			provider, store := newS3Provider(t, s3ContractConfig(), s3ProviderOptions{failures: map[string]s3Response{tc.method: failure}})
			var err error
			switch tc.method {
			case "HEAD":
				err = store.Check(t.Context())
			case "PUT":
				err = store.Put(t.Context(), "object", []byte("data"))
			case "GET":
				var data []byte
				data, err = store.Get(t.Context(), "object", 256)
				if len(data) != 0 {
					t.Fatal("returned object data on provider error")
				}
			}
			requireStorageError(t, err)
			requests := provider.history()
			if len(requests) != 1 || requests[0].method != tc.method || requests[0].response != failure {
				t.Fatalf("expected the provider to receive one %s and return %d %s", tc.method, tc.status, tc.code)
			}
		})
	}
}

func TestS3ReadBounds(t *testing.T) {
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	frame := encoder.EncodeAll([]byte("12345"), nil)
	// Exercise high expansion with a small, bounded fixture. Checking only
	// Content-Length or compressed bytes would accept this object.
	const limit = 256
	compact := encoder.EncodeAll(bytes.Repeat([]byte{'x'}, 64<<10), nil)
	if len(compact) >= limit {
		t.Fatalf("compressed fixture is %d bytes, must be smaller than %d", len(compact), limit)
	}
	for _, tc := range []struct {
		name string
		wire []byte
		max  int64
	}{
		{"truncated frame", frame[:len(frame)-1], 256},
		{"one byte over", frame, 4},
		{"high expansion", compact, limit},
		{"negative bound", frame, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, store := newS3Provider(t, s3ContractConfig(), s3ProviderOptions{})
			provider.mu.Lock()
			provider.objects["object"] = s3Request{body: tc.wire, header: http.Header{"Content-Type": {"application/zstd"}}}
			provider.mu.Unlock()
			got, err := store.Get(t.Context(), "object", tc.max)
			requireStorageError(t, err)
			if len(got) != 0 {
				t.Fatalf("returned %d bytes of a rejected object", len(got))
			}
			requests := provider.history()
			if tc.max < 0 {
				if len(requests) != 0 {
					t.Fatal("negative bound reached the provider")
				}
			} else if len(requests) != 1 || requests[0].method != "GET" || requests[0].response.status != http.StatusOK {
				t.Fatal("expected a successful provider GET before local rejection")
			}
		})
	}
}
