package hostconn

import "time"

// InstanceLostAfter is the instance-lost threshold shared by the management API health check (design P4B) and job recovery (design G52).
func InstanceLostAfter(c Config) time.Duration {
	return max(2*c.FlushInterval, c.HeartbeatTimeout)
}
