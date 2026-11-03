package output

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/klauspost/compress/zstd"
)

type Storage interface {
	Put(context.Context, string, []byte) error
	Get(context.Context, string, int64) ([]byte, error)
}

type Config struct {
	Bucket   string `yaml:"bucket"`
	Endpoint string `yaml:"endpoint"`
	Region   string `yaml:"region"`
}

type S3 struct {
	Client *s3.Client
	Bucket string
}

// Check is a read-only dependency probe; caller bounds the context (design G48).
func (s *S3) Check(ctx context.Context) error {
	_, err := s.Client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.Bucket)})
	if err != nil {
		return errors.New("output storage unavailable")
	}
	return nil
}

// Credentials come from the standard SDK credential chain, never YAML or argv.
// Bucket encryption and retention are operator-managed bucket policies.
func New(ctx context.Context, c Config) (*S3, error) {
	if c.Bucket == "" || c.Region == "" {
		return nil, errors.New("output bucket and region required")
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
			o.UsePathStyle = true
		}
	})
	return &S3{Client: client, Bucket: c.Bucket}, nil
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
		return err
	}
	compressed := w.EncodeAll(data, nil)
	w.Close()
	_, err = s.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key), Body: bytes.NewReader(compressed), ContentType: aws.String("application/zstd"), ServerSideEncryption: types.ServerSideEncryptionAes256})
	if err != nil {
		return errors.New("output object write failed")
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
