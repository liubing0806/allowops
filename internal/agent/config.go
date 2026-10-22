package agent

import (
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const ConfigFile = "/etc/allowops/agent.yaml"
const DataDirectory = "/var/lib/allowops"

const AgentALPN = "allowops-agent/1"
const JoinALPN = "allowops-join/1"
const MaxMessageBytes = 1024 * 1024
const MaxChunkBytes = 64 * 1024
const MaxConcurrentTasks = 4

type Config struct {
	Upstream       string            `yaml:"upstream" json:"upstream"`
	CAPin          string            `yaml:"ca_pin" json:"ca_pin"`
	ReportedLabels map[string]string `yaml:"reported_labels" json:"reported_labels"`
	Limits         Limits            `yaml:"limits" json:"limits"`
}

type Limits struct {
	MessageBytes     int           `yaml:"message_bytes" json:"message_bytes"`
	ChunkBytes       int           `yaml:"chunk_bytes" json:"chunk_bytes"`
	CatalogBytes     int64         `yaml:"catalog_bytes" json:"catalog_bytes"`
	ParameterBytes   int           `yaml:"parameter_bytes" json:"parameter_bytes"`
	ParameterDepth   int           `yaml:"parameter_depth" json:"parameter_depth"`
	ConcurrentTasks  int           `yaml:"concurrent_tasks" json:"concurrent_tasks"`
	CatalogPulls     int           `yaml:"catalog_pulls" json:"catalog_pulls"`
	ControlMessages  int           `yaml:"control_messages" json:"control_messages"`
	OutputQueueBytes int           `yaml:"output_queue_bytes" json:"output_queue_bytes"`
	ReceiveRate      int           `yaml:"receive_rate" json:"receive_rate"`
	ReceiveBurst     int           `yaml:"receive_burst" json:"receive_burst"`
	ReportedLabels   int           `yaml:"reported_labels" json:"reported_labels"`
	LabelKeyBytes    int           `yaml:"label_key_bytes" json:"label_key_bytes"`
	LabelValueBytes  int           `yaml:"label_value_bytes" json:"label_value_bytes"`
	ReconnectMin     time.Duration `yaml:"reconnect_min" json:"reconnect_min"`
	ReconnectMax     time.Duration `yaml:"reconnect_max" json:"reconnect_max"`
}

func (l Limits) defaults() Limits {
	for _, field := range []struct {
		value        *int
		defaultValue int
	}{{&l.MessageBytes, MaxMessageBytes}, {&l.ChunkBytes, MaxChunkBytes}, {&l.ParameterBytes, 64 * 1024}, {&l.ParameterDepth, 32}, {&l.ConcurrentTasks, MaxConcurrentTasks}, {&l.CatalogPulls, 1}, {&l.ControlMessages, 64}, {&l.OutputQueueBytes, 1024 * 1024}, {&l.ReceiveRate, 100}, {&l.ReceiveBurst, 200}, {&l.ReportedLabels, 128}, {&l.LabelKeyBytes, 128}, {&l.LabelValueBytes, 1024}} {
		if *field.value == 0 {
			*field.value = field.defaultValue
		}
	}
	if l.CatalogBytes == 0 {
		l.CatalogBytes = 64 * 1024 * 1024
	}
	if l.ReconnectMin == 0 {
		l.ReconnectMin = time.Second
	}
	if l.ReconnectMax == 0 {
		l.ReconnectMax = 30 * time.Second
	}
	return l
}

func (l Limits) validate() error {
	for _, value := range []int{l.MessageBytes, l.ChunkBytes, l.ParameterBytes, l.ParameterDepth, l.ConcurrentTasks, l.CatalogPulls, l.ControlMessages, l.OutputQueueBytes, l.ReceiveRate, l.ReceiveBurst, l.ReportedLabels, l.LabelKeyBytes, l.LabelValueBytes} {
		if value <= 0 {
			return errors.New("INVALID_LIMITS")
		}
	}
	if l.CatalogBytes <= 0 || l.MessageBytes > 1<<31-1 || l.ChunkBytes >= l.MessageBytes || l.OutputQueueBytes < l.ChunkBytes || l.ConcurrentTasks > 1<<31-1 || l.ReportedLabels < 3 || l.ReconnectMin < time.Millisecond || l.ReconnectMax < l.ReconnectMin {
		return errors.New("INVALID_LIMITS")
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	var config Config
	f, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer f.Close()
	d := yaml.NewDecoder(io.LimitReader(f, MaxMessageBytes+1))
	d.KnownFields(true)
	if err := d.Decode(&config); err != nil {
		return config, errors.New("INVALID_CONFIG")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return config, errors.New("INVALID_CONFIG")
	}
	return config, config.validate()
}

func upstreamURL(address string) (string, error) {
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("INVALID_UPSTREAM")
	}
	return "https://" + u.Host, nil
}

func (c Config) validate() error {
	limits := c.Limits.defaults()
	if err := limits.validate(); err != nil {
		return err
	}
	if _, err := upstreamURL(c.Upstream); err != nil {
		return err
	}
	if _, err := parsePin(c.CAPin); err != nil {
		return err
	}
	if len(c.ReportedLabels) > limits.ReportedLabels-3 {
		return errors.New("TOO_MANY_LABELS")
	}
	for key, value := range c.ReportedLabels {
		if len(key) == 0 || len(key) > limits.LabelKeyBytes || len(value) > limits.LabelValueBytes || strings.ContainsAny(key+value, "\x00\r\n") {
			return errors.New("INVALID_LABELS")
		}
	}
	return nil
}
