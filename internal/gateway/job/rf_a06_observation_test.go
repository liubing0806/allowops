package job_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/liubing0806/allowops/internal/gateway/audit"
	"github.com/liubing0806/allowops/internal/gateway/output"
)

// All A06 stages share a monotonic clock. No URLs, object keys, error messages,
// headers or payloads are recorded.
type rfA06Observation struct {
	start  time.Time
	mu     sync.Mutex
	stages []string
}

func (o *rfA06Observation) mark(stage string, err error) {
	if o == nil {
		return
	}
	code := ""
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		code = pgerr.Code
	}
	var apierr smithy.APIError
	if errors.As(err, &apierr) {
		code = apierr.ErrorCode()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stages = append(o.stages, fmt.Sprintf("A06 phase=%s elapsed_us=%d error_type=%T code=%q", stage, time.Since(o.start).Microseconds(), err, code))
}

func (o *rfA06Observation) dump(t *testing.T) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, stage := range o.stages {
		t.Log(stage)
	}
}

type rfA06HTTP struct {
	base        s3.HTTPClient
	observation *rfA06Observation
	calls       atomic.Int32
}

func (c *rfA06HTTP) Do(r *http.Request) (*http.Response, error) {
	n := c.calls.Add(1)
	c.observation.mark(fmt.Sprintf("s3_http_%d_%s_start", n, r.Method), nil)
	response, err := c.base.Do(r)
	status := 0
	if response != nil {
		status = response.StatusCode
	}
	c.observation.mark(fmt.Sprintf("s3_http_%d_return_status_%d", n, status), err)
	return response, err
}

func rfA06ObserveS3(original *output.S3, o *rfA06Observation) *output.S3 {
	options := original.Client.Options()
	options.HTTPClient = &rfA06HTTP{base: options.HTTPClient, observation: o}
	options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
		return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("rfA06Observe", func(ctx context.Context, input middleware.InitializeInput, next middleware.InitializeHandler) (out middleware.InitializeOutput, metadata middleware.Metadata, err error) {
			name := middleware.GetOperationName(ctx)
			o.mark("s3_api_"+name+"_start", nil)
			out, metadata, err = next.HandleInitialize(ctx, input)
			o.mark("s3_api_"+name+"_return", err)
			return
		}), middleware.Before)
	})
	return &output.S3{Client: s3.New(options), Bucket: original.Bucket}
}

type rfA06Audit struct {
	audit.Appender
	observation *rfA06Observation
}

func (a rfA06Audit) Append(ctx context.Context, p audit.Payload) (audit.Event, error) {
	if p.Operation != "store_output" {
		return a.Appender.Append(ctx, p)
	}
	a.observation.mark("output_audit_start", nil)
	event, err := a.Appender.Append(ctx, p)
	a.observation.mark("output_audit_return", err)
	return event, err
}
