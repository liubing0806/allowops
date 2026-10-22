package output_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"github.com/liubing0806/allowops/internal/testseaweedfs"
)

func TestSeaweedFSRoundTripAndBounds(t *testing.T) {
	s := testseaweedfs.Start(t)
	options := s.Client.Options()
	if options.RequestChecksumCalculation != aws.RequestChecksumCalculationWhenRequired || options.ResponseChecksumValidation != aws.ResponseChecksumValidationWhenRequired {
		t.Fatal("SDK checksum settings must be WHEN_REQUIRED")
	}
	t.Log("aws-sdk-go-v2 request and response checksum settings: WHEN_REQUIRED")
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	step := uint32(0)
	plain := output.Key(at, "job-20261014-0001", "host-id", nil, "stdout")
	withStep := output.Key(at, "job-20261014-0001", "host-id", &step, "stdout")
	if plain != "outputs/2026/10/14/job-20261014-0001/host-id.stdout.zst" || withStep != "outputs/2026/10/14/job-20261014-0001/host-id.step-0.stdout.zst" {
		t.Fatalf("keys=%q %q", plain, withStep)
	}
	data := bytes.Repeat([]byte("redacted output\n"), 1000)
	if _, err := s.Client.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String("sdk-probe"), Body: bytes.NewReader(data), ServerSideEncryption: types.ServerSideEncryptionAes256}); err != nil {
		t.Fatalf("SeaweedFS SDK upload WHEN_REQUIRED + AES256: %v", err)
	}
	if err := s.Put(context.Background(), plain, data); err != nil {
		t.Fatal(err)
	}
	read, err := s.Get(context.Background(), plain, int64(len(data)))
	if err != nil || !bytes.Equal(read, data) {
		t.Fatalf("round trip length=%d error=%v", len(read), err)
	}
	if _, err := s.Get(context.Background(), plain, 10); err == nil {
		t.Fatal("accepted oversized decompressed output")
	}
	if err := s.Put(context.Background(), withStep, nil); err != nil {
		t.Fatal(err)
	}
	read, err = s.Get(context.Background(), withStep, 0)
	if err != nil || len(read) != 0 {
		t.Fatalf("empty output=%d error=%v", len(read), err)
	}
}

func TestSeaweedFSRetentionLifecycle(t *testing.T) {
	s := testseaweedfs.Start(t)
	ctx := context.Background()
	rule := types.LifecycleRule{ID: aws.String("output-retention"), Status: types.ExpirationStatusEnabled, Filter: &types.LifecycleRuleFilter{Prefix: aws.String("outputs/")}, Expiration: &types.LifecycleExpiration{Days: aws.Int32(30)}}
	if _, err := s.Client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{Bucket: aws.String(s.Bucket), LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: []types.LifecycleRule{rule}}}); err != nil {
		t.Fatalf("SeaweedFS retention PutBucketLifecycleConfiguration: %v", err)
	}
	got, err := s.Client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(s.Bucket)})
	if err != nil {
		t.Fatalf("SeaweedFS retention GetBucketLifecycleConfiguration: %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Expiration == nil || aws.ToInt32(got.Rules[0].Expiration.Days) != 30 || got.Rules[0].Status != types.ExpirationStatusEnabled {
		t.Fatalf("SeaweedFS retention rules=%v", got.Rules)
	}
	t.Log("SeaweedFS accepted and returned enabled 30-day outputs/ expiration rule; elapsed expiry is not measured")
}
