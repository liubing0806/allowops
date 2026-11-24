package output

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/klauspost/compress/zstd"
)

type Storage interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string, int64) ([]byte, error)
}

type Config struct {
	Bucket               string `yaml:"bucket"`
	Endpoint             string `yaml:"endpoint"`
	Region               string `yaml:"region"`
	UsePathStyle         *bool  `yaml:"use_path_style"`
	ServerSideEncryption string `yaml:"server_side_encryption"`
}

type S3 struct {
	Client *s3.Client
	Bucket string

	skipServerSideEncryption bool
}

type storageError struct {
	message string
	details slog.Value
}

func (e *storageError) Error() string { return e.message }

// ErrorDetails returns safe log fields for an output storage failure.
func ErrorDetails(err error) slog.Value {
	var failure *storageError
	if errors.As(err, &failure) {
		return failure.details
	}
	var operation *smithy.OperationError
	if errors.As(err, &operation) {
		err = operation.Unwrap()
	}
	var attempts *retry.MaxAttemptsError
	if errors.As(err, &attempts) {
		err = attempts.Unwrap()
	}
	var attrs []slog.Attr
	var response interface {
		error
		HTTPStatusCode() int
	}
	if errors.As(err, &response) {
		if status := response.HTTPStatusCode(); status > 0 {
			attrs = append(attrs, slog.Int("http_status", status))
		}
		if cause := errors.Unwrap(response); cause != nil {
			err = cause
		}
	}
	attrs = append(attrs, slog.String("error_type", fmt.Sprintf("%T", err)))
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		attrs = append(attrs, slog.String("s3_error_code", safeS3ErrorCode(apiErr.ErrorCode())))
	}
	return slog.GroupValue(attrs...)
}

func safeS3ErrorCode(code string) string {
	// S3-compatible servers control the response, including the Code field.
	switch code {
	case "AccessDenied", "AuthorizationHeaderMalformed", "BadRequest", "EncryptionTypeMismatch",
		"ExpiredToken", "Forbidden", "IncorrectEndpoint", "InternalError", "InvalidAccessKeyId",
		"InvalidArgument", "InvalidBucketName", "InvalidEncryptionAlgorithmError", "InvalidRequest",
		"InvalidToken", "MethodNotAllowed", "NoSuchBucket", "NotFound", "NotImplemented",
		"PermanentRedirect", "RequestTimeTooSkewed", "ServiceUnavailable", "SignatureDoesNotMatch",
		"SlowDown", "TemporaryRedirect":
		return code
	default:
		return "Unknown"
	}
}

// Check is a read-only dependency probe; caller bounds the context (design G48).
func (s *S3) Check(ctx context.Context) error {
	_, err := s.Client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.Bucket)})
	if err != nil {
		failure := &storageError{message: "output storage unavailable", details: ErrorDetails(err)}
		slog.ErrorContext(ctx, failure.message, "storage_error", failure.details)
		return failure
	}
	return nil
}

// Credentials come from the standard SDK credential chain, never YAML or argv.
// Bucket encryption and retention are operator-managed bucket policies.
func New(ctx context.Context, c Config) (*S3, error) {
	if c.Bucket == "" || c.Region == "" {
		return nil, errors.New("output bucket and region required")
	}
	switch c.ServerSideEncryption {
	case "", string(types.ServerSideEncryptionAes256), "none":
	default:
		return nil, errors.New("output server_side_encryption must be AES256 or none")
	}
	if c.Endpoint != "" {
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return nil, errors.New("invalid output endpoint")
		}
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.Region))
	if err != nil {
		return nil, errors.New("load output credentials")
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
		o.UsePathStyle = c.Endpoint != ""
		if c.UsePathStyle != nil {
			o.UsePathStyle = *c.UsePathStyle
		}
	})
	return &S3{Client: client, Bucket: c.Bucket, skipServerSideEncryption: c.ServerSideEncryption == "none"}, nil
}

// Key uses the immutable host ID. Steps have a zero-based .step-N component;
// absent step and step zero cannot collide. IDs are gateway-generated.
func Key(at time.Time, jobID, hostID string, step *uint32, stream string) string {
	part := ""
	if step != nil {
		part = fmt.Sprintf(".step-%d", *step)
	}
	return fmt.Sprintf("outputs/%s/%s/%s%s.%s.zst", at.UTC().Format("2006/01/02"), jobID, hostID, part, stream)
}

func (s *S3) Put(ctx context.Context, key string, data []byte) error {
	w, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return &storageError{message: "output object write failed", details: ErrorDetails(err)}
	}
	compressed := w.EncodeAll(data, nil)
	w.Close()
	input := &s3.PutObjectInput{
		Bucket: aws.String(s.Bucket), Key: aws.String(key),
		Body: bytes.NewReader(compressed), ContentType: aws.String("application/zstd"),
	}
	if !s.skipServerSideEncryption {
		input.ServerSideEncryption = types.ServerSideEncryptionAes256
	}
	_, err = s.Client.PutObject(ctx, input)
	if err != nil {
		return &storageError{message: "output object write failed", details: ErrorDetails(err)}
	}
	return nil
}

func (s *S3) Get(ctx context.Context, key string, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, errors.New("invalid output bound")
	}
	r, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key)})
	if err != nil {
		return nil, errors.New("output object unavailable")
	}
	defer r.Body.Close()
	d, err := zstd.NewReader(r.Body, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(max(1<<20, maxBytes+1))))
	if err != nil {
		return nil, errors.New("invalid output compression")
	}
	defer d.Close()
	b, err := io.ReadAll(io.LimitReader(d, maxBytes+1))
	if err != nil || int64(len(b)) > maxBytes {
		return nil, errors.New("output object exceeds bound or is corrupt")
	}
	return b, nil
}
