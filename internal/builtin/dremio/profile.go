package dremio

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The download of POST /apiv2/support/{id}/download is a zip with header.json
// and one profile_attempt_N.json per attempt. The profile is the JSON of
// UserBitShared.QueryProfile. Only the fields below are read: the other fields
// of the 100 KB to several MB document (jsonPlan, relInfoMap, the Base64
// batchSchema of the data sets) are skipped by the decoder.

const (
	// maxZipEntries bounds the central directory that is read before any entry.
	maxZipEntries = 64
	// maxTopOperators is the largest value of top_n.
	maxTopOperators = 50
	// maxPushdownStatements and maxPushdownRunes bound the statements that the
	// plan shows for the data sources.
	maxPushdownStatements = 10
	maxPushdownRunes      = 2000
	// maxErrorRunes bounds the first line of the error message of a failed job.
	maxErrorRunes = 300
)

var profileEntry = regexp.MustCompile(`^profile_attempt_([0-9]{1,4})\.json$`)

// jdbcPushdown matches the SQL that the plan hands to a JDBC data source. The
// statement ends at "]) : rowType", which a line of the plan has after it.
var jdbcPushdown = regexp.MustCompile(`(?s)Jdbc\(sql=\[(.*?)\]\) : rowType`)

var errProfile = errors.New("dremio profile is not valid")

// extractProfile returns the JSON of the last attempt in the zip. The zip comes
// from the server over the network, so it is read as untrusted data: the number
// of entries is bounded, the size an entry declares is checked, and the bytes
// that are read are counted against the same limit because the declared size
// can be wrong. Names are matched against a fixed pattern and are never used as
// paths.
func extractProfile(data []byte, maxBytes int64) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(zr.File) > maxZipEntries {
		return nil, errProfile
	}
	var chosen *zip.File
	chosenAttempt := -1
	for _, f := range zr.File {
		m := profileEntry.FindStringSubmatch(f.Name)
		if m == nil {
			continue
		}
		attempt, _ := strconv.Atoi(m[1])
		if attempt > chosenAttempt {
			chosen, chosenAttempt = f, attempt
		}
	}
	if chosen == nil {
		return nil, errProfile
	}
	if chosen.UncompressedSize64 > uint64(maxBytes) {
		return nil, fmt.Errorf("dremio profile exceeds %d bytes", maxBytes)
	}
	rc, err := chosen.Open()
	if err != nil {
		return nil, errProfile
	}
	defer rc.Close()
	out, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, errProfile
	}
	if int64(len(out)) > maxBytes {
		return nil, fmt.Errorf("dremio profile exceeds %d bytes", maxBytes)
	}
	return out, nil
}

type rawProfile struct {
	Start         int64  `json:"start"`
	End           int64  `json:"end"`
	PlanningStart int64  `json:"planningStart"`
	PlanningEnd   int64  `json:"planningEnd"`
	State         int    `json:"state"`
	User          string `json:"user"`
	Plan          string `json:"plan"`
	Error         string `json:"error"`
	CancelReason  string `json:"cancelReason"`
	Foreman       struct {
		MaxDirectMemory int64 `json:"maxDirectMemory"`
	} `json:"foreman"`
	StateList []struct {
		State     int   `json:"state"`
		StartTime int64 `json:"startTime"`
	} `json:"stateList"`
	PlanPhases []struct {
		PhaseName      string `json:"phaseName"`
		DurationMillis int64  `json:"durationMillis"`
	} `json:"planPhases"`
	FragmentProfile []struct {
		MajorFragmentID int `json:"majorFragmentId"`
		Minor           []struct {
			MinorFragmentID int `json:"minorFragmentId"`
			Operators       []struct {
				OperatorID               int   `json:"operatorId"`
				OperatorType             int   `json:"operatorType"`
				ProcessNanos             int64 `json:"processNanos"`
				WaitNanos                int64 `json:"waitNanos"`
				PeakLocalMemoryAllocated int64 `json:"peakLocalMemoryAllocated"`
				OutputRecords            int64 `json:"outputRecords"`
				Inputs                   []struct {
					Records int64 `json:"records"`
				} `json:"inputProfile"`
			} `json:"operatorProfile"`
		} `json:"minorFragmentProfile"`
	} `json:"fragmentProfile"`
	Acceleration struct {
		Accelerated      bool `json:"accelerated"`
		NumSubstitutions int  `json:"numSubstitutions"`
		Layouts          []struct {
			LayoutID string `json:"layoutId"`
			Name     string `json:"name"`
			NumUsed  int    `json:"numUsed"`
		} `json:"layoutProfiles"`
	} `json:"accelerationProfile"`
	Nodes []struct {
		MaxMemoryUsed int64 `json:"maxMemoryUsed"`
	} `json:"nodeProfile"`
	Scheduling struct {
		QueueName string `json:"queueName"`
	} `json:"resourceSchedulingProfile"`
}

// Phase is the time a job spent in one state of its attempt.
type Phase struct {
	Name string `json:"name"`
	Ms   int64  `json:"ms"`
}

// Operator sums one operator over its instances (the minor fragments of its
// major fragment).
type Operator struct {
	Fragment     int    `json:"fragment"`
	ID           int    `json:"id"`
	Type         string `json:"type"`
	Instances    int    `json:"instances"`
	ProcessMs    int64  `json:"process_ms"`
	WaitMs       int64  `json:"wait_ms"`
	RecordsIn    int64  `json:"records_in"`
	RecordsOut   int64  `json:"records_out"`
	PeakMemory   int64  `json:"peak_memory_bytes"`
	SkewRatio    string `json:"skew_ratio,omitempty"`
	processNanos int64
	waitNanos    int64
	skew         float64
}

// Acceleration says whether reflections answered the query. Reflections lists
// the ones the plan used; Considered counts all that the planner looked at.
type Acceleration struct {
	Accelerated   bool     `json:"accelerated"`
	Substitutions int      `json:"substitutions"`
	Considered    int      `json:"considered"`
	Reflections   []string `json:"reflections,omitempty"`
}

// Summary is the structured view of a job profile. Strings that come from the
// server (user, queue, error, SQL, reflection names) are passed through the
// caller's mask by summarize.
type Summary struct {
	JobID            string       `json:"job_id"`
	State            string       `json:"state"`
	User             string       `json:"user,omitempty"`
	Queue            string       `json:"queue,omitempty"`
	TotalMs          int64        `json:"total_ms"`
	PlanningMs       int64        `json:"planning_ms"`
	Phases           []Phase      `json:"phases"`
	PlanningTop      []Phase      `json:"planning_top,omitempty"`
	PeakMemory       int64        `json:"peak_memory_bytes"`
	DirectMemory     int64        `json:"direct_memory_bytes,omitempty"`
	ScanRecords      int64        `json:"scan_records"`
	Operators        []Operator   `json:"operators"`
	OperatorsOmitted int          `json:"operators_omitted,omitempty"`
	PushdownSQL      []string     `json:"pushdown_sql,omitempty"`
	Acceleration     Acceleration `json:"acceleration"`
	Error            string       `json:"error,omitempty"`
	Hits             []Hit        `json:"hits"`

	// all holds every operator, for the rules; Operators is its top-N cut.
	// errorText is the unmasked message, which only the rules read.
	all       []Operator
	errorText string
}

// summarize parses the profile JSON. mask is applied to every string that the
// server supplied; it must not be nil.
func summarize(jobID string, data []byte, topN int, mask func(string) string) (Summary, error) {
	var p rawProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return Summary{}, errProfile
	}
	s := Summary{
		JobID: jobID, State: nameOf(queryStates[:], p.State, "STATE"), User: mask(p.User), Queue: mask(p.Scheduling.QueueName),
		DirectMemory: p.Foreman.MaxDirectMemory,
		Phases:       []Phase{},
		Operators:    []Operator{},
		Hits:         []Hit{},
	}
	if p.End > p.Start && p.Start > 0 {
		s.TotalMs = p.End - p.Start
	}
	if p.PlanningEnd > p.PlanningStart && p.PlanningStart > 0 {
		s.PlanningMs = p.PlanningEnd - p.PlanningStart
	}
	for i, st := range p.StateList {
		name := nameOf(attemptStates[:], st.State, "STATE")
		if name == "COMPLETED" || name == "CANCELED" || name == "FAILED" {
			continue
		}
		var ms int64
		if i+1 < len(p.StateList) {
			ms = max(0, p.StateList[i+1].StartTime-st.StartTime)
		}
		s.Phases = append(s.Phases, Phase{Name: name, Ms: ms})
	}
	for _, ph := range p.PlanPhases {
		if ph.DurationMillis > 0 {
			s.PlanningTop = append(s.PlanningTop, Phase{Name: mask(truncateRunes(ph.PhaseName, 120)), Ms: ph.DurationMillis})
		}
	}
	slices.SortStableFunc(s.PlanningTop, func(a, b Phase) int { return int(b.Ms - a.Ms) })
	if len(s.PlanningTop) > 5 {
		s.PlanningTop = s.PlanningTop[:5]
	}
	for _, n := range p.Nodes {
		s.PeakMemory = max(s.PeakMemory, n.MaxMemoryUsed)
	}
	s.all = aggregateOperators(&p)
	for _, op := range s.all {
		if isScan(op.Type) {
			s.ScanRecords += op.RecordsOut
		}
	}
	ranked := slices.Clone(s.all)
	slices.SortStableFunc(ranked, func(a, b Operator) int { return int((b.processNanos + b.waitNanos) - (a.processNanos + a.waitNanos)) })
	if topN > len(ranked) {
		topN = len(ranked)
	}
	s.Operators = ranked[:topN]
	s.OperatorsOmitted = len(ranked) - topN
	for _, m := range jdbcPushdown.FindAllStringSubmatch(p.Plan, -1) {
		if len(s.PushdownSQL) == maxPushdownStatements {
			break
		}
		sql := strings.TrimSpace(m[1])
		if sql != "" && !slices.Contains(s.PushdownSQL, mask(truncateRunes(sql, maxPushdownRunes))) {
			s.PushdownSQL = append(s.PushdownSQL, mask(truncateRunes(sql, maxPushdownRunes)))
		}
	}
	s.Acceleration = Acceleration{Accelerated: p.Acceleration.Accelerated, Substitutions: p.Acceleration.NumSubstitutions, Considered: len(p.Acceleration.Layouts)}
	for _, l := range p.Acceleration.Layouts {
		if l.NumUsed > 0 {
			s.Acceleration.Reflections = append(s.Acceleration.Reflections, mask(truncateRunes(cmpFirst(l.Name, l.LayoutID), 120)))
		}
	}
	if s.Acceleration.Substitutions > 0 || len(s.Acceleration.Reflections) > 0 {
		s.Acceleration.Accelerated = true
	}
	message := p.Error
	if message == "" {
		message = p.CancelReason
	}
	if message != "" {
		s.errorText = message
		line, _, _ := strings.Cut(message, "\n")
		s.Error = mask(truncateRunes(line, maxErrorRunes))
	}
	s.Hits = evaluate(&s)
	return s, nil
}

func cmpFirst(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func isScan(operatorType string) bool {
	return strings.HasSuffix(operatorType, "_SUB_SCAN") || operatorType == "PARQUET_ROW_GROUP_SCAN" || operatorType == "BOOST_PARQUET"
}

// aggregateOperators groups the operator profiles of all minor fragments by
// major fragment and operator id. The skew ratio is the largest process time of
// an instance divided by the mean of all instances; one instance has no skew.
func aggregateOperators(p *rawProfile) []Operator {
	type key struct{ major, id int }
	index := map[key]int{}
	var ops []Operator
	var maxNanos []int64
	for _, frag := range p.FragmentProfile {
		for _, minor := range frag.Minor {
			for _, o := range minor.Operators {
				k := key{frag.MajorFragmentID, o.OperatorID}
				i, ok := index[k]
				if !ok {
					i = len(ops)
					index[k] = i
					ops = append(ops, Operator{Fragment: frag.MajorFragmentID, ID: o.OperatorID, Type: operatorTypeName(o.OperatorType)})
					maxNanos = append(maxNanos, 0)
				}
				op := &ops[i]
				op.Instances++
				op.processNanos += o.ProcessNanos
				op.waitNanos += o.WaitNanos
				op.RecordsOut += o.OutputRecords
				for _, in := range o.Inputs {
					op.RecordsIn += in.Records
				}
				op.PeakMemory = max(op.PeakMemory, o.PeakLocalMemoryAllocated)
				maxNanos[i] = max(maxNanos[i], o.ProcessNanos)
			}
		}
	}
	for i := range ops {
		op := &ops[i]
		op.ProcessMs = op.processNanos / 1e6
		op.WaitMs = op.waitNanos / 1e6
		if op.Instances > 1 && op.processNanos > 0 {
			op.skew = float64(maxNanos[i]) * float64(op.Instances) / float64(op.processNanos)
			op.SkewRatio = strconv.FormatFloat(math.Round(op.skew*100)/100, 'f', 2, 64)
		}
	}
	return ops
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "..."
}
