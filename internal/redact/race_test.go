//go:build race

package redact

import "time"

// The race detector slows the scan down about 15 times.
const linearScanBound = 60 * time.Second
