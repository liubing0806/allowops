package job

import (
	"errors"
	"time"
)

type Config struct {
	WaitSeconds    uint32 `yaml:"wait_seconds"`
	MaxWaitSeconds uint32 `yaml:"max_wait_seconds"`
	BatchSize      uint32 `yaml:"batch_size"`
	MaxFailures    uint32 `yaml:"max_failures"`
}

func DefaultConfig() Config {
	return Config{WaitSeconds: 30, MaxWaitSeconds: 120, BatchSize: 20, MaxFailures: 5}
}

func (c Config) validate() error {
	if c.MaxWaitSeconds == 0 || c.MaxWaitSeconds > 120 || c.WaitSeconds > c.MaxWaitSeconds || c.BatchSize == 0 {
		return errors.New("invalid job limits")
	}
	return nil
}

const ResponseBytes = 32 << 10
const GroupBytes = 4 << 10
const pollInterval = 20 * time.Millisecond
