package dremio

import (
	"strconv"
	"strings"
)

// Hit is a rule that matched a profile. Evidence holds the measured values,
// Cause the usual reasons and Advice the next step. docs/builtin-dremio.md
// lists the rules.
type Hit struct {
	Rule     string         `json:"rule"`
	Evidence map[string]any `json:"evidence"`
	Cause    string         `json:"cause"`
	Advice   string         `json:"advice"`
}

// Initial thresholds. They were set on the profiles of the local environment
// (docs/builtin-dremio.md, section "Rules") and are not calibrated on
// production data.
const (
	planningMinMs        = 250
	planningMinPercent   = 25
	scanRecordsThreshold = 100_000
	joinRecordsThreshold = 100_000
	nestedLoopMinRecords = 1_000
	joinOutputMinRecords = 100_000
	joinOutputFactor     = 10
	memoryPercent        = 20
)

type rule func(*Summary) *Hit

var rules = []rule{ruleFail1, rulePlan1, ruleScan1, ruleJoin1, ruleJoin2, ruleJoin3, ruleMem1}

// evaluate runs every rule. The result is never nil.
func evaluate(s *Summary) []Hit {
	hits := []Hit{}
	for _, r := range rules {
		if h := r(s); h != nil {
			hits = append(hits, *h)
		}
	}
	return hits
}

func ruleFail1(s *Summary) *Hit {
	if s.State != "FAILED" && s.State != "CANCELED" {
		return nil
	}
	return &Hit{
		Rule:     "DR-FAIL-1",
		Evidence: map[string]any{"state": s.State, "category": errorCategory(s.errorText)},
		Cause:    "The job ended without a result. The category comes from the error text of the profile: object not found, access denied, resource limit, syntax or validation error, or execution error.",
		Advice:   "Read the error field. For an object that was not found, check the path and the data source; for a resource limit, see DR-MEM-1; for a cancellation, check who cancelled it with the job op.",
	}
}

func rulePlan1(s *Summary) *Hit {
	if s.PlanningMs < planningMinMs || s.TotalMs <= 0 || s.PlanningMs*100 < s.TotalMs*planningMinPercent {
		return nil
	}
	h := &Hit{
		Rule:     "DR-PLAN-1",
		Evidence: map[string]any{"planning_ms": s.PlanningMs, "total_ms": s.TotalMs},
		Cause:    "Planning takes a large part of the run time: metadata of data sets is retrieved or refreshed, the statement has many tables, views or UNION branches, or the plan has many alternatives.",
		Advice:   "See planning_top for the slowest planning phases. For metadata phases, refresh the metadata of the data set before the query; for a long statement, split it or reference fewer views.",
	}
	if len(s.PlanningTop) > 0 {
		h.Evidence["slowest_phase"] = s.PlanningTop[0].Name
		h.Evidence["slowest_phase_ms"] = s.PlanningTop[0].Ms
	}
	return h
}

func ruleScan1(s *Summary) *Hit {
	if s.ScanRecords < scanRecordsThreshold {
		return nil
	}
	return &Hit{
		Rule:     "DR-SCAN-1",
		Evidence: map[string]any{"scan_records": s.ScanRecords, "threshold": scanRecordsThreshold},
		Cause:    "The scans read many rows from the data sources into Dremio: no filter that the source can apply, or filters, aggregates or limits that were not pushed down.",
		Advice:   "Compare pushdown_sql with the statement. Add filters on partition or key columns, select fewer columns, and prefer expressions that the source supports so that they are pushed down.",
	}
}

func joinOperators(s *Summary, types ...string) []Operator {
	var found []Operator
	for _, op := range s.all {
		for _, t := range types {
			if op.Type == t {
				found = append(found, op)
			}
		}
	}
	return found
}

func ruleJoin1(s *Summary) *Hit {
	var records int64
	var names []string
	for _, op := range joinOperators(s, "HASH_JOIN", "MERGE_JOIN") {
		if op.RecordsIn >= joinRecordsThreshold {
			records += op.RecordsIn
			names = append(names, op.Type+"@"+strconv.Itoa(op.Fragment)+"-"+strconv.Itoa(op.ID))
		}
	}
	if len(names) == 0 {
		return nil
	}
	return &Hit{
		Rule:     "DR-JOIN-1",
		Evidence: map[string]any{"join_input_records": records, "operators": strings.Join(names, ","), "threshold": joinRecordsThreshold},
		Cause:    "A join runs in Dremio on many rows: the inputs come from different data sources, or the join condition cannot be pushed to the source.",
		Advice:   "Check the data sources of both inputs. Join tables of one source in that source, reduce one side with filters or an aggregate before the join, or put the small side in a reflection.",
	}
}

func ruleJoin2(s *Summary) *Hit {
	for _, op := range joinOperators(s, "NESTED_LOOP_JOIN") {
		if op.RecordsIn >= nestedLoopMinRecords {
			return &Hit{
				Rule:     "DR-JOIN-2",
				Evidence: map[string]any{"operator": "NESTED_LOOP_JOIN@" + strconv.Itoa(op.Fragment) + "-" + strconv.Itoa(op.ID), "input_records": op.RecordsIn, "threshold": nestedLoopMinRecords},
				Cause:    "The join has no equality condition, or only a range or OR condition. Dremio compares every pair of rows.",
				Advice:   "Add an equality condition on a key, or rewrite the range condition (for example with a bucket column). Reduce both inputs before the join.",
			}
		}
	}
	return nil
}

func ruleJoin3(s *Summary) *Hit {
	for _, op := range joinOperators(s, "HASH_JOIN", "MERGE_JOIN") {
		if op.RecordsOut >= joinOutputMinRecords && op.RecordsOut >= op.RecordsIn*joinOutputFactor {
			return &Hit{
				Rule:     "DR-JOIN-3",
				Evidence: map[string]any{"operator": op.Type + "@" + strconv.Itoa(op.Fragment) + "-" + strconv.Itoa(op.ID), "input_records": op.RecordsIn, "output_records": op.RecordsOut, "factor": joinOutputFactor},
				Cause:    "The join returns many times more rows than it reads: the join key is not unique on either side, so every row matches many rows.",
				Advice:   "Check the uniqueness of the join key on both sides. Aggregate or deduplicate one side on the key before the join.",
			}
		}
	}
	return nil
}

func ruleMem1(s *Summary) *Hit {
	if s.DirectMemory <= 0 || s.PeakMemory*100 < s.DirectMemory*memoryPercent {
		return nil
	}
	return &Hit{
		Rule:     "DR-MEM-1",
		Evidence: map[string]any{"peak_memory_bytes": s.PeakMemory, "direct_memory_bytes": s.DirectMemory, "threshold_percent": memoryPercent},
		Cause:    "One node used a large part of its direct memory for this query: a join, aggregate or sort over many rows or wide rows, or a statement with many branches that run at the same time.",
		Advice:   "See operators for the ones with the highest peak_memory_bytes. Reduce rows and columns before them, or split the statement. Raise the direct memory of the executors only after that.",
	}
}
