//go:build !race

package api

import "time"

// The 21,810 evaluations took 2.2s locally on f5ab600.
const fullPolicyTrialBudget = 30 * time.Second
