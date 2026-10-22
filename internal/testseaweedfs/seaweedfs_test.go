package testseaweedfs_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/liubing0806/allowops/internal/testseaweedfs"
)

// RR-a-01: the first business PutObject after Start must not hit the
// ~4.96 s first-write slow path of a freshly created SeaweedFS container.
// The slow path is probabilistic (5 of 17 containers in RR-a), so the test
// creates several containers and records every first-Put latency.
func TestStartFirstBusinessPutIsFast(t *testing.T) {
	const containers = 6
	const limit = time.Second
	for i := range containers {
		t.Run(fmt.Sprintf("container_%d", i+1), func(t *testing.T) {
			store := testseaweedfs.Start(t)
			started := time.Now()
			err := store.Put(t.Context(), fmt.Sprintf("outputs/rr-a-01/first-%d.stdout.zst", i), []byte("first business put"))
			elapsed := time.Since(started)
			t.Logf("first business Put after Start: %s", elapsed)
			if err != nil {
				t.Fatalf("first business Put error=%v", err)
			}
			if elapsed >= limit {
				t.Fatalf("first business Put took %s; want < %s", elapsed, limit)
			}
		})
	}
}
