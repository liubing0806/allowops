// Package builtin defines the unredacted result returned to the outer executor.
package builtin

import "time"

// Defaults remain provisional until the builtin handler default limits and exit
// code rules are finalized (decisions A15, A16).
const (
	DefaultTimeout                     = 10 * time.Second
	DefaultLogMaxFiles                 = 50
	DefaultLogMaxScan            int64 = 256 << 20
	DefaultLogMaxMatches               = 1000
	DefaultLogMaxContext               = 20
	DefaultHTTPMaxResponseBytes  int64 = 64 << 10
	DefaultHTTPMaxHeaderBytes    int64 = 64 << 10
	DefaultRedisMaxResponseBytes int64 = 64 << 10
	DefaultMySQLMaxResponseBytes int64 = 64 << 10
	DefaultRedisMaxScanCount           = 1000
	DefaultRedisScanCount              = 100
	DefaultStarRocksMaxRows            = 500
	DefaultStarRocksMaxBytes     int64 = 1 << 20
	ExitSuccess                        = 0
	ExitFailure                        = 1
)

// Result contains raw stdout bounded only by handler resource limits.
// Handlers never implement the action's max_output limit. The caller MUST
// redact Stdout first, then apply filters, then truncate to max_output before
// forwarding output. Output truncation is tracked by the executor separately
// from this result's resource-limit flag.
// ExitCode is 0 on success and 1 on error. Resource limits may produce partial
// success or reject a request with an error, depending on the handler.
type Result struct {
	Stdout string `json:"stdout"`
	// Truncated reports only a resource limit (scan, matches, files or response
	// bytes). It never reports the executor's final output truncation.
	Truncated bool `json:"truncated"`
	ExitCode  int  `json:"exit_code"`
}
