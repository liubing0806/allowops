package jvmtarget

import "fmt"

// Identify returns the JVM that has the pid and the start time, without a lookup by target.
// It fails with ErrProcessChanged when the pid belongs to another process or to none.
// Whether the process is a JVM is not checked: the caller uses it to reach a process
// whose pid and start time it recorded earlier.
func (r *Resolver) Identify(pid int, startTime uint64) (*JVM, error) {
	j, err := r.identify(pid)
	if err != nil {
		return nil, err
	}
	if j.StartTime != startTime {
		return nil, fmt.Errorf("process %d: %w", pid, ErrProcessChanged)
	}
	return j, nil
}
