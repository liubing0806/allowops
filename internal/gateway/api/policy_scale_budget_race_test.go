//go:build race

package api

import "time"

// Allow for race instrumentation and parallel packages on shared CI workers.
// Tighten this budget after optimizing full policy trials.
const fullPolicyTrialBudget = 4 * time.Minute
