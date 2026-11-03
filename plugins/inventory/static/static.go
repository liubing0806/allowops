// Package static reads inventory from a local YAML file at gateway startup.
package static

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/inventory"
	"gopkg.in/yaml.v3"
)

func init() { plugin.Register(Module{}) }

type Module struct {
	File     string `yaml:"file"`
	entities []inventory.Entity
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.static", New: func() plugin.Module { return &Module{} }}
}

type entityFile struct {
	Kind      string            `yaml:"kind"`
	Name      string            `yaml:"name"`
	Attrs     map[string]string `yaml:"attrs"`
	Hosts     []string          `yaml:"hosts"`
	Selector  string            `yaml:"selector"`
	DependsOn []string          `yaml:"depends_on"`
}

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
var attrPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func (m *Module) Provision(ctx context.Context, h plugin.Host) error {
	// O_NONBLOCK keeps a FIFO from blocking startup; the file type check
	// below then rejects it.
	f, err := os.OpenFile(m.File, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("inventory file must be a regular file")
	}
	const maxBytes = 4 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxBytes {
		return fmt.Errorf("inventory file exceeds 4MB")
	}
	var file struct {
		Entities []entityFile `yaml:"entities"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return err
	}
	entities := make([]inventory.Entity, 0, len(file.Entities))
	seen := map[[2]string]bool{}
	// Errors identify entities by position only: names and attributes may
	// hold credentials and the error reaches logs and stderr.
	for i, e := range file.Entities {
		key := [2]string{e.Kind, e.Name}
		if seen[key] {
			return fmt.Errorf("inventory entity #%d: duplicate kind and name", i+1)
		}
		seen[key] = true
		if !kindPattern.MatchString(e.Kind) || len(e.Name) == 0 || len(e.Name) > 128 || len(e.Selector) > 512 {
			return fmt.Errorf("inventory entity #%d: invalid kind, name or selector", i+1)
		}
		values := []string{e.Name, e.Selector}
		values = append(values, e.Hosts...)
		values = append(values, e.DependsOn...)
		for k, v := range e.Attrs {
			if !attrPattern.MatchString(k) {
				return fmt.Errorf("inventory entity #%d: invalid attribute key", i+1)
			}
			values = append(values, v)
		}
		for _, v := range values {
			if strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("inventory entity #%d: strings must not contain newlines", i+1)
			}
		}
		entities = append(entities, inventory.Entity{Kind: e.Kind, Name: e.Name, Attrs: e.Attrs, Hosts: e.Hosts, Selector: e.Selector, DependsOn: e.DependsOn})
	}
	m.entities = entities
	return nil
}

func (m *Module) Resolve(ctx context.Context, q inventory.Query) ([]inventory.Entity, error) {
	out := []inventory.Entity{}
	for _, e := range m.entities {
		if q.Kind != "" && e.Kind != q.Kind {
			continue
		}
		e.Attrs = maps.Clone(e.Attrs)
		e.Hosts = slices.Clone(e.Hosts)
		e.DependsOn = slices.Clone(e.DependsOn)
		out = append(out, e)
	}
	return out, nil
}
