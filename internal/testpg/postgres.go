// Package testpg provisions only disposable PostgreSQL on the local Docker Unix
// socket. It never accepts a DSN or remote Docker endpoint from the environment.
package testpg

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const Image = "postgres@sha256:051f7b7b3abdd564d5d1bd1e8c4b9c1b6e77087d1dd22020ede611c096a272e0"

func Start(t *testing.T) string {
	t.Helper()
	const socket = "/var/run/docker.sock"
	probe, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		if os.Getenv("ALLOWOPS_REQUIRE_DOCKER") == "1" {
			t.Fatalf("local Docker required: %v", err)
		}
		t.Skipf("local Docker unavailable: %v", err)
	}
	probe.Close()
	t.Setenv("DOCKER_HOST", "unix://"+socket)
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	t.Setenv("TESTCONTAINERS_HOST_OVERRIDE", "127.0.0.1")
	t.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", socket)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	password := rand.Text()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: testcontainers.ContainerRequest{Image: Image, Env: map[string]string{"POSTGRES_USER": "fixture", "POSTGRES_PASSWORD": password, "POSTGRES_DB": "fixture"}, ExposedPorts: []string{"5432/tcp"}, HostConfigModifier: func(h *container.HostConfig) {
		h.PortBindings = network.PortMap{network.MustParsePort("5432/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1")}}}
	}, WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2)}, Started: true})
	if c != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := c.Terminate(ctx); err != nil {
				t.Errorf("terminate local PostgreSQL: %v", err)
			}
		})
	}
	if err != nil {
		t.Fatalf("start local PostgreSQL: %v", err)
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	u := url.URL{Scheme: "postgres", Host: net.JoinHostPort("127.0.0.1", port.Port()), Path: "/fixture", User: url.UserPassword("fixture", password), RawQuery: "sslmode=disable"}
	t.Logf("local PostgreSQL container %s image=%s port=%s", c.GetContainerID()[:12], Image, port.Port())
	return fmt.Sprint(u.String())
}
