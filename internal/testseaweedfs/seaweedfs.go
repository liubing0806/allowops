// Package testseaweedfs provisions a disposable SeaweedFS S3 gateway on the local Docker socket.
package testseaweedfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/liubing0806/allowops/internal/gateway/output"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Version and digest are fixed together for reproducible local S3 tests.
const Version = "4.46"
const Image = "chrislusf/seaweedfs:4.46@sha256:08d516132314207d10c8e37cbffc1f32b147d870169688734cc61c6231625b62"

func Start(t *testing.T) *output.S3 {
	t.Helper()
	probe, err := net.DialTimeout("unix", "/var/run/docker.sock", time.Second)
	if err != nil {
		if os.Getenv("ALLOWOPS_REQUIRE_DOCKER") == "1" {
			t.Fatalf("local Docker required: %v", err)
		}
		t.Skipf("local Docker unavailable: %v", err)
	}
	probe.Close()
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	t.Setenv("TESTCONTAINERS_HOST_OVERRIDE", "127.0.0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	user, password := rand.Text(), rand.Text()
	credentialsJSON, err := json.Marshal(map[string]any{"identities": []any{map[string]any{"name": "fixture", "credentials": []any{map[string]string{"accessKey": user, "secretKey": password}}, "actions": []string{"Admin", "Read", "Write", "List", "Tagging"}}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{
		Image:        Image,
		User:         "0:0",
		Entrypoint:   []string{"weed"},
		Env:          map[string]string{"WEED_S3_SSE_KEY": rand.Text()},
		Files:        []testcontainers.ContainerFile{{Reader: bytes.NewReader(credentialsJSON), ContainerFilePath: "/etc/allowops-s3.json", FileMode: 0600}},
		Cmd:          []string{"server", "-s3", "-s3.config=/etc/allowops-s3.json", "-dir=/data", "-ip=127.0.0.1", "-ip.bind=0.0.0.0", "-master.volumeSizeLimitMB=16", "-volume.max=8"},
		ExposedPorts: []string{"8333/tcp"}, HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = network.PortMap{network.MustParsePort("8333/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}}}
		}, WaitingFor: wait.ForHTTP("/").WithPort("8333/tcp").WithStatusCodeMatcher(func(status int) bool { return status == 403 }),
	}, Started: true})
	if c != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := c.Terminate(ctx, testcontainers.StopTimeout(time.Second)); err != nil {
				t.Errorf("terminate local SeaweedFS: %v", err)
			}
		})
	}
	if err != nil {
		t.Fatalf("start local SeaweedFS: %v", err)
	}
	port, err := c.MappedPort(ctx, "8333/tcp")
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(user, password, "")}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://127.0.0.1:" + port.Port())
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	const bucket = "outputs"
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("create fixture bucket failed")
	}
	if _, err := client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{Bucket: aws.String(bucket), ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{Rules: []types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{SSEAlgorithm: types.ServerSideEncryptionAes256}}}}}); err != nil {
		t.Fatal("enable fixture bucket encryption failed")
	}
	store := &output.S3{Client: client, Bucket: bucket}
	// A fresh container serves its first PutObject slowly (about 5 s in roughly a third of
	// the containers). Absorb that here with the same write path business code uses, so
	// tests with tight deadlines never see it. The fixture object is deleted afterwards.
	const warmupKey = "fixture/warmup.zst"
	if err := store.Put(ctx, warmupKey, []byte("warmup")); err != nil {
		t.Fatal("warm up fixture bucket failed")
	}
	if _, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(warmupKey)}); err != nil {
		t.Fatal("delete fixture warmup object failed")
	}
	t.Logf("local SeaweedFS container %s image=%s port=%s", c.GetContainerID()[:12], Image, port.Port())
	return store
}
