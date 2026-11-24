package cluster

import (
	"bytes"
	"slices"
	"strings"
)

// AnomalyReason constants matching the unified three-tier table (design 5.1).
const (
	ReasonTimeout              = "timeout"
	ReasonNonZeroExit          = "nonzero_exit"
	ReasonTaskFailed           = "task_failed"
	ReasonTaskUnsupported      = "task_unsupported"
	ReasonTaskCancelled        = "task_cancelled"
	ReasonTaskSkipped          = "task_skipped"
	ReasonErrorReason          = "error_reason"
	ReasonStderrPresent        = "stderr_present"
	ReasonMinorityCluster      = "minority_cluster"
	ReasonMetricOutlier        = "metric_outlier"
	ReasonMajorityNormal       = "majority_normal"
	ReasonClusterLimitOverflow = "cluster_limit_overflow"
)

// SortGroups sorts output groups in-place using the deterministic unified
// Anomaly-First three-tier comparator:
//
//   - Tier 0 (FAILURE): sub-rank ASC -> host_count DESC -> reason ASC -> exit_code ASC -> first_host ASC
//   - Tier 1 (ANOMALY): sub-rank ASC -> host_count ASC -> first_host ASC
//   - Tier 2 (NORMAL):  sub-rank ASC -> host_count DESC -> first_host ASC
func SortGroups(groups []Group) {
	slices.SortFunc(groups, compareGroups)
}

func compareGroups(a, b Group) int {
	if a.Severity != b.Severity {
		if a.Severity < b.Severity {
			return -1
		}
		return 1
	}
	if a.SeveritySub != b.SeveritySub {
		if a.SeveritySub < b.SeveritySub {
			return -1
		}
		return 1
	}

	switch a.Severity {
	case SeverityFailure:
		if a.HostCount != b.HostCount {
			if a.HostCount > b.HostCount {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.Reason, b.Reason); c != 0 {
			return c
		}
		if c := compareExitCodePtr(a.ExitCode, b.ExitCode); c != 0 {
			return c
		}
	case SeverityAnomaly:
		if a.HostCount != b.HostCount {
			if a.HostCount < b.HostCount {
				return -1
			}
			return 1
		}
	default: // SeverityNormal
		if a.HostCount != b.HostCount {
			if a.HostCount > b.HostCount {
				return -1
			}
			return 1
		}
	}

	if c := strings.Compare(firstHost(a.Hosts), firstHost(b.Hosts)); c != 0 {
		return c
	}
	if c := bytes.Compare(a.TemplateHash, b.TemplateHash); c != 0 {
		return c
	}
	if c := bytes.Compare(a.StdoutHash, b.StdoutHash); c != 0 {
		return c
	}
	if c := bytes.Compare(a.StderrHash, b.StderrHash); c != 0 {
		return c
	}
	return strings.Compare(a.AnomalyReason, b.AnomalyReason)
}

func compareExitCodePtr(a, b *int32) int {
	if a == nil && b == nil {
		return 0
	}
	if a != nil && b == nil {
		return -1
	}
	if a == nil && b != nil {
		return 1
	}
	if *a < *b {
		return -1
	}
	if *a > *b {
		return 1
	}
	return 0
}

func firstHost(hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	return hosts[0]
}
