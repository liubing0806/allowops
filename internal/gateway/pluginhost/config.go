package pluginhost

import (
	"bytes"
	"fmt"
	"regexp"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ID       string        `yaml:"id"`
	Module   string        `yaml:"module"`
	Disabled bool          `yaml:"disabled"`
	Required bool          `yaml:"required"`
	Timeout  time.Duration `yaml:"timeout"`
	Config   yaml.Node     `yaml:"config"`
}

var yamlErrorLine = regexp.MustCompile(`line (\d+)`)

func decodeConfig(c Config, m plugin.Module) error {
	if hasAlias(&c.Config) {
		return fmt.Errorf("plugin %s: config contains YAML alias", c.ID)
	}
	data, err := yaml.Marshal(&c.Config)
	if err != nil {
		return fmt.Errorf("plugin %s: %w", c.ID, err)
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
