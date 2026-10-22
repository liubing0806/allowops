package hostconn

import (
	"fmt"
	"time"
)

// Defaults follow the confirmed Q1/A14 policy. Values may only tighten protocol caps.
type Config struct {
	Version                 string        `yaml:"version"`
	CertificateTTL          time.Duration `yaml:"certificate_ttl"`
	SingleJoinTTL           time.Duration `yaml:"single_join_ttl"`
	MultiJoinTTL            time.Duration `yaml:"multi_join_ttl"`
	HeartbeatInterval       time.Duration `yaml:"heartbeat_interval"`
	HeartbeatTimeout        time.Duration `yaml:"heartbeat_timeout"`
	FlushInterval           time.Duration `yaml:"flush_interval"`
	MessageBytes            int           `yaml:"message_bytes"`
	ChunkBytes              int           `yaml:"chunk_bytes"`
	EnvelopeBytes           int           `yaml:"envelope_bytes"`
	ActionBytes             int           `yaml:"action_bytes"`
	QueueMessages           int           `yaml:"queue_messages"`
	QueueBytes              int           `yaml:"queue_bytes"`
	ReceiveRate             int           `yaml:"receive_rate"`
	ReceiveBurst            int           `yaml:"receive_burst"`
	MaxInflight             int           `yaml:"max_inflight"`
	ReportedLabelCount      int           `yaml:"reported_label_count"`
	ReportedLabelKeyBytes   int           `yaml:"reported_label_key_bytes"`
	ReportedLabelValueBytes int           `yaml:"reported_label_value_bytes"`
	MailboxRows             int64         `yaml:"mailbox_rows"`
	MailboxBytes            int64         `yaml:"mailbox_bytes"`
	MailboxTTL              time.Duration `yaml:"mailbox_ttl"`
	CleanupInterval         time.Duration `yaml:"cleanup_interval"`
	ReconnectMin            time.Duration `yaml:"reconnect_min"`
	ReconnectMax            time.Duration `yaml:"reconnect_max"`
	ShutdownGrace           time.Duration `yaml:"shutdown_grace"`
}

func DefaultConfig() Config {
	return Config{Version: "0.1.0", CertificateTTL: 24 * time.Hour, SingleJoinTTL: 24 * time.Hour, MultiJoinTTL: 24 * time.Hour,
		HeartbeatInterval: 15 * time.Second, HeartbeatTimeout: 45 * time.Second, FlushInterval: 5 * time.Minute,
		MessageBytes: 1 << 20, ChunkBytes: 64 << 10, EnvelopeBytes: 64 << 20, ActionBytes: 256 << 10,
		QueueMessages: 64, QueueBytes: 1 << 20, ReceiveRate: 100, ReceiveBurst: 200, MaxInflight: 4,
		ReportedLabelCount: 128, ReportedLabelKeyBytes: 128, ReportedLabelValueBytes: 1024,
		MailboxRows: 1024, MailboxBytes: 64 << 20, MailboxTTL: time.Minute, CleanupInterval: time.Minute,
		ReconnectMin: time.Second, ReconnectMax: 30 * time.Second, ShutdownGrace: 10 * time.Second}
}

func (c Config) Validate() error {
	if err := CheckVersion(c.Version, c.Version); err != nil {
		return err
	}
	if c.CertificateTTL <= 0 || c.SingleJoinTTL <= 0 || c.MultiJoinTTL <= 0 || c.HeartbeatInterval <= 0 || c.HeartbeatTimeout < c.HeartbeatInterval || c.FlushInterval <= 0 || c.MailboxTTL <= 0 || c.CleanupInterval <= 0 || c.ReconnectMin < 0 || c.ReconnectMax < c.ReconnectMin || c.ShutdownGrace <= 0 {
		return fmt.Errorf("invalid gateway duration configuration")
	}
	for _, v := range []struct{ n, cap int }{{c.MessageBytes, 1 << 20}, {c.ChunkBytes, 64 << 10}, {c.EnvelopeBytes, 64 << 20}, {c.ActionBytes, 256 << 10}, {c.QueueMessages, 64}, {c.QueueBytes, 1 << 20}, {c.ReceiveRate, 100}, {c.ReceiveBurst, 200}, {c.MaxInflight, 4}, {c.ReportedLabelCount, 128}, {c.ReportedLabelKeyBytes, 128}, {c.ReportedLabelValueBytes, 1024}} {
		if v.n <= 0 || v.n > v.cap {
			return fmt.Errorf("gateway limits must be positive and within protocol caps")
		}
	}
	if c.MessageBytes <= c.ChunkBytes+1024 || c.QueueBytes < c.MessageBytes || c.ReconnectMax > 30*time.Second || c.MailboxRows <= 0 || c.MailboxBytes < int64(c.MessageBytes)*2 {
		return fmt.Errorf("invalid gateway buffer configuration")
	}
	return nil
}
