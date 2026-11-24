// Package cluster implements deterministic, bounded, regex-free lexical
// normalization, two-pass fleet output clustering, Anomaly-First ranking,
// numeric distribution/outlier detection, and bounded cross-job diffing.
//
// All entry points operate strictly on bounded, already-redacted output
// previews (at most MaxPreviewBytesPerStream per stream) with deterministic
// integer ceilings instead of wall-clock timeouts. Repeated calls with the
// same input always yield byte-identical results, and all emitted float64
// statistics satisfy the finite-float invariant (!math.IsNaN && !math.IsInf).
package cluster

// Deterministic hard ceilings preventing DoS and guaranteeing byte-identical
// outputs across runs regardless of CPU load.
const (
	MaxPreviewBytesPerStream = 4096 // matches job.GroupBytes and DB CHECK
	MaxLinesPerPreview       = 128  // max lines scanned per stream
	MaxLineBytes             = 1024 // max bytes scanned per line
	MaxTasks                 = 5000 // max tasks in normalized mode; deterministic fallback to exact above this
	MaxClusters              = 256  // max normalized clusters for succeeded tasks
	MaxFailureClusters       = 128  // max normalized clusters for Tier 0 failure tasks
	MaxSlotsPerTask          = 64   // max numeric slots extracted per task
	MaxSlotsPerCluster       = 64   // max numeric slots tracked per cluster
	MaxSamplesPerSlot        = 5000 // aligned with MaxTasks so tail outliers are never dropped
	MaxReportedVariances     = 5    // max numeric variance entries reported per cluster
	MaxLabelBytes            = 64   // max UTF-8 byte length for sanitized output-derived labels/units
	MaxJSONDepth             = 8    // max JSON recursion depth
	MaxJSONKeys              = 128  // max keys per JSON object
	MaxJSONArrayItems        = 64   // max elements scanned per JSON array
	MaxDetailedPatternDiffs  = 32   // max top pattern changes receiving bounded line-level diff
	MaxDiffLinesPerEntry     = 6    // max removed/added representative lines per pattern diff
	MaxDiffLineBytes         = 256  // max UTF-8 bytes per representative diff line
)

const (
	// MaxMetricDrifts caps the number of significant drifts returned by Diff.
	MaxMetricDrifts = 10
	// MaxOutlierHosts caps outlier hostnames reported per MetricVariance.
	MaxOutlierHosts = 3
	// ConciseSampleHosts is the maximum sample hostnames included per group in concise mode.
	ConciseSampleHosts = 2

	// RankingAnomalyFirst identifies the unified three-tier ranking order.
	RankingAnomalyFirst = "anomaly_first"
)

// GroupingMode controls whether clustering/diffing compares exact hashes or
// normalized output templates.
type GroupingMode string

const (
	GroupingExact      GroupingMode = "exact"
	GroupingNormalized GroupingMode = "normalized"
)

// PreviewMode identifies the normalization mode selected for a stream.
type PreviewMode string

const (
	PreviewModeAuto   PreviewMode = ""
	PreviewModeText   PreviewMode = "text"
	PreviewModeJSON   PreviewMode = "json"
	PreviewModeNDJSON PreviewMode = "ndjson"
)

// TaskStatus mirrors allowops.v1.TaskStatus without importing protobuf types.
type TaskStatus uint8

const (
	StatusUnspecified TaskStatus = iota
	StatusPending
	StatusRunning
	StatusSucceeded
	StatusFailed
	StatusTimeout
	StatusOffline
	StatusSkipped
	StatusCancelled
	StatusUnsupported
)

// String returns the canonical lowercase name of the task status.
func (s TaskStatus) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusRunning:
		return "running"
	case StatusSucceeded:
		return "succeeded"
	case StatusFailed:
		return "failed"
	case StatusTimeout:
		return "timeout"
	case StatusOffline:
		return "offline"
	case StatusSkipped:
		return "skipped"
	case StatusCancelled:
		return "cancelled"
	case StatusUnsupported:
		return "unsupported"
	default:
		return "unspecified"
	}
}

// Severity identifies the three-tier Anomaly-First classification.
type Severity uint8

const (
	SeverityUnspecified Severity = iota
	SeverityFailure              // Tier 0: timeout, non-zero exit, failed, unsupported, cancelled, skipped, error reason
	SeverityAnomaly              // Tier 1: stderr_present, minority_cluster, metric_outlier
	SeverityNormal               // Tier 2: majority_normal, cluster_limit_overflow
)

// String returns the canonical lowercase name of the severity tier.
func (s Severity) String() string {
	switch s {
	case SeverityFailure:
		return "failure"
	case SeverityAnomaly:
		return "anomaly"
	case SeverityNormal:
		return "normal"
	default:
		return "unspecified"
	}
}
