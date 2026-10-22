package api

import (
	"context"
	"github.com/liubing0806/allowops/internal/gateway/hostconn"
	"time"
)

// InstanceLostAfter is the shared P4B health and G52 recovery threshold.
func InstanceLostAfter(c hostconn.Config) time.Duration {
	return max(2*c.FlushInterval, c.HeartbeatTimeout)
}

// JobStatistics applies the same authorization as job queries (G48/A21).
type JobStatistics interface {
	Statistics(context.Context) (running, failed uint64, err error)
}
type ObjectStorageHealth interface{ Check(context.Context) error }

// ConfigureJobDependencies is called during startup before serving requests.
func (s *Service) ConfigureJobDependencies(jobs JobStatistics, storage ObjectStorageHealth) {
	s.jobStatistics = jobs
	s.objectStorage = storage
}
