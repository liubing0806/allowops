package hostconn

import "time"

// InstanceLostAfter is the shared P4B health and G52 recovery threshold.
func InstanceLostAfter(c Config) time.Duration {
	return max(2*c.FlushInterval, c.HeartbeatTimeout)
}
