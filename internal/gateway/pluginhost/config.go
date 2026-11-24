package pluginhost

import (
	"bytes"
	"fmt"
	"regexp"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"gopkg.in/yaml.v3"
)

type ConfigList []Config

type Config struct {
	ID                        string            `yaml:"id"`
	Module                    string            `yaml:"module"`
	Disabled                  bool              `yaml:"disabled"`
	Required                  bool              `yaml:"required"`
	Timeout                   time.Duration     `yaml:"timeout"`
	MaxConcurrency            int               `yaml:"max_concurrency"`
	Egress                    []string          `yaml:"egress"`
	AllowPrivateEgress        bool              `yaml:"allow_private_egress"`
	AllowCrossOriginRedirects bool              `yaml:"allow_cross_origin_redirects"`
	CAFile                    string            `yaml:"ca_file"`
	Credentials               map[string]string `yaml:"credentials"`
	AllowProjectedCredentials bool              `yaml:"allow_projected_credentials"`
	Config                    yaml.Node         `yaml:"config"`
}

func (list *ConfigList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("plugins: invalid configuration at line %d", value.Line)
	}
	configs := make(ConfigList, 0, len(value.Content))
	for _, node := range value.Content {
		var c Config
		if err := c.UnmarshalYAML(node); err != nil {
			return err
		}
		configs = append(configs, c)
	}
	*list = configs
	return nil
}

func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	invalid := fmt.Errorf("invalid plugin configuration at line %d", value.Line)
	if value.Kind != yaml.MappingNode || hasAlias(value) {
		return invalid
	}
	data, err := yaml.Marshal(value)
	if err != nil {
		return invalid
	}
	type plainConfig Config
	var decoded plainConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&decoded); err != nil {
		return invalid
	}
	*c = Config(decoded)
	return nil
}

var yamlErrorLine = regexp.MustCompile(`line (\d+)`)

func decodeConfig(c Config, m plugin.Module) error {
	if hasAlias(&c.Config) {
		return fmt.Errorf("plugin %s: config contains YAML alias", c.ID)
	}
	data, err := yaml.Marshal(&c.Config)
	if err != nil {
		return fmt.Errorf("plugin %s: invalid config", c.ID)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(m); err != nil {
		// yaml.v3 errors quote field names and values; keep only the line.
		if line := yamlErrorLine.FindStringSubmatch(err.Error()); line != nil {
			return fmt.Errorf("plugin %s: invalid config at line %s", c.ID, line[1])
		}
		return fmt.Errorf("plugin %s: invalid config", c.ID)
	}
	return nil
}

func hasAlias(n *yaml.Node) bool {
	if n.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range n.Content {
		if hasAlias(child) {
			return true
		}
	}
	return false
}
