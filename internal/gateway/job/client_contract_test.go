package job_test

import (
	"github.com/liubing0806/allowops/internal/gateway/job"
	"github.com/liubing0806/allowops/internal/gateway/mcp"
)

// P6M consumes the same authenticated in-process job methods. Client also
// exposes ListTaskSteps, which is additional to the MCP service contract.
var _ mcp.JobService = (job.Client)(nil)
var _ mcp.JobService = (*job.Service)(nil)
