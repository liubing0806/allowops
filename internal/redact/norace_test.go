//go:build !race

package redact

import "time"

const linearScanBound = 2 * time.Second
