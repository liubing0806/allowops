package api

import (
	"context"
)

// JobStatistics applies the same authorization as job queries (design G48, A21).
type JobStatistics interface {
	Statistics(context.Context) (running, failed uint64, err error)
}

type ObjectStorageHealth interface{ Check(context.Context) error }

// ConfigureJobDependencies is called during startup before serving requests.
func (s *Service) ConfigureJobDependencies(jobs JobStatistics, storage ObjectStorageHealth) {
	s.jobStatistics = jobs
	s.objectStorage = storage
}
