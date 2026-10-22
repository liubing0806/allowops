package params

// JSONSchema produces the action parameter schema used by MCP (draft 2020-12).
func JSONSchema(defs map[string]Definition) (map[string]any, error) {
	if err := ValidateDefinitions(defs); err != nil {
		return nil, err
	}
	properties := make(map[string]any, len(defs))
	required := []string{}
	for _, name := range names(defs) {
		d := defs[name]
		p := map[string]any{"description": d.Description}
		switch d.Type {
		case Bool:
			p["type"] = "boolean"
		case StringArray:
			p["type"] = "array"
			item := map[string]any{"type": "string", "pattern": `^(?:[^-\r\n\u0000][^\r\n\u0000]*)?$`}
			if d.MaxLen > 0 {
				item["maxLength"] = d.MaxLen
			}
			if d.Regex != "" {
				item["allOf"] = []any{map[string]any{"pattern": d.Regex}}
			}
			p["items"] = item
			if d.MaxItems > 0 {
				p["maxItems"] = d.MaxItems
			}
		case Enum:
			p["type"] = "string"
			p["enum"] = d.Values
		case Int:
			p["type"] = "integer"
			if d.Min != nil {
				p["minimum"] = *d.Min
			}
			if d.Max != nil {
				p["maximum"] = d.Max
			}
		case String:
			p["type"] = "string"
			if d.Regex != "" {
				p["pattern"] = d.Regex
			}
			if d.MaxLen > 0 {
				p["maxLength"] = d.MaxLen
			}
			p["allOf"] = []any{map[string]any{"pattern": `^(?:[^-\r\n\u0000][^\r\n\u0000]*)?$`}}
		case Duration:
			p["type"] = "string"
			p["description"] = d.Description + "; allowed: " + allowed(d)
			p["x-allowops-max"] = d.Max
		case URL:
			p["type"] = "string"
			p["format"] = "uri"
			p["x-allowops-allowed-prefixes"] = d.AllowedPrefixes
		case Path:
			p["type"] = "string"
			p["pattern"] = `^(?:[^-\r\n\u0000][^\r\n\u0000]*)?$`
			p["x-allowops-allowed-roots"] = d.AllowedRoots
		}
		if d.Default != nil {
			p["default"] = d.Default
		} else if !d.Optional {
			required = append(required, name)
		}
		properties[name] = p
	}
	return map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": properties, "required": required, "additionalProperties": false}, nil
}
