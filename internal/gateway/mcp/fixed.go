package mcp

import (
	"regexp"

	"github.com/liubing0806/allowops/internal/gateway/job"
)

// actionName matches catalog action names.
var actionName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// fixedReservedToolNames are read-reserved catalog names and can never be
// catalog actions.
var fixedReservedToolNames = []string{"hosts_search", "jobs_get", "jobs_list", "jobs_cancel", "jobs_diff", "entities_search", "changes_list", "runbooks_search", "runbooks_read"}

// progressiveMetaToolNames are authoring/publish-reserved tool names; older
// signed catalogs may still contain actions with these names.
var progressiveMetaToolNames = []string{"actions_search", "actions_invoke_read", "actions_invoke_write", "actions_invoke_dangerous"}

// actionRisks lists the risks in actions_search order.
var actionRisks = []string{"read", "write", "dangerous"}

func invokeToolName(risk string) string {
	return "actions_invoke_" + risk
}

func fixedTools(cfg job.Config, sources ...string) []ToolDefinition {
	text := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description, "minLength": 1}
	}
	jobID := func() map[string]any {
		return text("Short job ID returned by an action tool, for example job-20261014-0001.")
	}
	cursor := func() map[string]any {
		return text("Opaque next_cursor from the previous page. Restart without this field if the snapshot changes.")
	}
	object := func(properties map[string]any, required ...string) map[string]any {
		schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
		if len(required) > 0 {
			schema["required"] = required
		}
		return schema
	}
	tools := []ToolDefinition{
		{Name: "hosts_search", Description: "Search hosts by a label selector or a hostname, not both; without either, list all hosts visible to this identity with pagination. Returns hostnames, labels, online status, total count and label distribution. Selector syntax is comma-separated key=value conjunctions. Labels exceeding the result budget are marked labels_truncated; label distributions use label_counts_truncated. Narrow the selector or use the console/CLI to inspect complete labels.", Annotations: ToolAnnotations{ReadOnlyHint: true}, InputSchema: object(map[string]any{"selector": text("Label selector (A10)."), "hostname": text("Globally unique hostname."), "next_cursor": cursor()})},
		{Name: "jobs_get", Description: "Read a job summary. With host, read lossless paginated host output as data_base64 with encoding=base64 (default); pass next_offset as offset to continue. With host and encoding=text, read the page as UTF-8 text in data; next_offset stops at a complete character, and output that is not valid UTF-8 returns ENCODING_NOT_TEXT, after which read it with encoding=base64. Summary counts cover all tasks; groups and offline_hosts cover the current page. P6 summaries may already be truncated; the truncated marker is preserved. Composite action output requires step_index and is read one step at a time. Output additionally requires view_output authorization.", Annotations: ToolAnnotations{ReadOnlyHint: true}, InputSchema: object(map[string]any{"job_id": jobID(), "host": text("Hostname whose complete output is requested."), "wait_seconds": waitSchema(cfg), "response_format": formatSchema(), "grouping": groupingSchema("exact"), "next_cursor": cursor(), "stream": map[string]any{"type": "string", "description": "Host output stream.", "enum": []string{"stdout", "stderr"}, "default": "stdout"}, "step_index": outputStepSchema(), "offset": map[string]any{"type": "integer", "description": "Byte offset in stored output; use next_offset to continue.", "minimum": 0, "maximum": uint64(^uint64(0))}, "encoding": map[string]any{"type": "string", "description": "Host output encoding: base64 returns data_base64; text returns UTF-8 data or ENCODING_NOT_TEXT. Only with host.", "enum": []string{"base64", "text"}, "default": "base64"}}, "job_id")},
		{Name: "jobs_list", Description: "List recent jobs belonging to the current authenticated service account or CLI user.", Annotations: ToolAnnotations{ReadOnlyHint: true}, InputSchema: object(map[string]any{"next_cursor": cursor()})},
		{Name: "jobs_cancel", Description: "Cancel a job: stop future batches and terminate running task process groups. Service accounts may only cancel their own jobs; users require execution authorization on every job host.", InputSchema: object(map[string]any{"job_id": jobID()}, "job_id")},
		{Name: "jobs_diff", Description: "Compare two finished, non-denied jobs of the same action aligned by immutable host_id. Defaults to grouping=normalized (action tools and jobs_get default to exact). Returns host set changes (added/removed/replaced), degradation-first status transitions, anomaly-first output pattern changes with bounded line diffs, and significant numeric metric drifts. Results are bounded to 32 KiB with exact counts preserved and no next_cursor pagination; inspect individual hosts with jobs_get(job_id, host). Derived labels and units in metric_drifts come from untrusted host output. Requires view_jobs and view_output on every host in both jobs.", Annotations: ToolAnnotations{ReadOnlyHint: true}, InputSchema: object(map[string]any{"base_job_id": text("Short job ID of the baseline job, for example job-20261014-0001."), "target_job_id": text("Short job ID of the target job to compare against the baseline, for example job-20261014-0002."), "grouping": groupingSchema("normalized"), "only_changed": map[string]any{"type": "boolean", "description": "When true (default), return only changed output patterns; when false, also append unchanged pattern clusters within the 32 KiB budget.", "default": true}}, "base_job_id", "target_job_id")},
	}
	if len(sources) > 0 {
		tools = append(tools, ToolDefinition{Name: "entities_search", Description: "Search inventory entities by exact kind and case-insensitive name substring. Dependencies refer to kind/name within the same source. Returned selectors and hostnames can be used as action targets; action authorization is checked separately. Results may be truncated; narrow the query for more detail. recommended_actions lists, per returned entity kind, up to 10 actions this identity may see whose entity_kinds include it; this is a policy precheck hint, every call is still authorized per host, and recommended_actions_truncated marks omitted recommendations.", Annotations: ToolAnnotations{ReadOnlyHint: true}, InputSchema: object(map[string]any{
			"kind":    map[string]any{"type": "string", "description": "Exact entity kind; omit or leave empty for all kinds."},
			"name":    map[string]any{"type": "string", "description": "Case-insensitive name substring; omit or leave empty for all names."},
			"sources": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": sources}, "description": "Inventory instance IDs; omit or leave empty for all available sources."},
			"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
		})})
	}
	for i := range tools {
		tools[i].Description += toolInstructions
	}
	return tools
}

func fixedPluginTools(cfg job.Config, inventorySources, changeSources, knowledgeSources []string) []ToolDefinition {
	tools := fixedTools(cfg, inventorySources...)
	if len(changeSources) > 0 {
		tools = append(tools, changesTool(changeSources))
	}
	if len(knowledgeSources) > 0 {
		tools = append(tools, runbooksSearchTool(knowledgeSources), runbooksReadTool(knowledgeSources))
	}
	return tools
}

func actionsSearchTool() ToolDefinition {
	metadata := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description, "pattern": metadataName.String()}
	}
	return ToolDefinition{Name: "actions_search", Description: "Find catalog actions this identity may run. Filter by query words, exact names, toolset, tag, risk, entity_kind or hostname; all filters combine. Each result names its invoke_tool (actions_invoke_read, actions_invoke_write or actions_invoke_dangerous); include_schema adds input_schema with the signed params schema and effective limits. Results are ordered read, write, dangerous, then by name, and paginated with next_cursor; the first page counts matches per toolset. A hostname keeps actions policy allows on that host now; this is a precheck and every call is still authorized." + toolInstructions, Annotations: ToolAnnotations{ReadOnlyHint: true}, InputSchema: map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
		"query":          map[string]any{"type": "string", "description": "Whitespace-separated words; every word must match name, description, toolset, tags or entity_kinds, ignoring case.", "minLength": 1, "maxLength": 200},
		"names":          map[string]any{"type": "array", "description": "Exact action names.", "items": map[string]any{"type": "string", "pattern": actionName.String()}, "minItems": 1, "maxItems": 20, "uniqueItems": true},
		"toolset":        metadata("Exact toolset."),
		"tag":            metadata("Keep actions with this tag."),
		"entity_kind":    metadata("Keep actions for this inventory entity kind."),
		"risk":           map[string]any{"type": "string", "enum": actionRisks},
		"hostname":       map[string]any{"type": "string", "description": "Keep actions policy allows on this host; unknown or hidden hosts return no actions.", "minLength": 1},
		"include_schema": map[string]any{"type": "boolean", "description": "Add input_schema to each result.", "default": false},
		"limit":          map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
		"next_cursor":    map[string]any{"type": "string", "description": "Opaque next_cursor from the previous page. Restart without this field if the snapshot changes.", "minLength": 1},
	}}}
}

// invokeTool is actions_invoke_<risk>. Each risk has its own tool, so that a
// client can approve read actions without approving write or dangerous ones.
func invokeTool(risk string, cfg job.Config) ToolDefinition {
	annotations := ToolAnnotations{ReadOnlyHint: risk == "read"}
	if risk != "read" {
		destructive := risk == "dangerous"
		annotations.DestructiveHint = &destructive
	}
	props := map[string]any{
		"action":          map[string]any{"type": "string", "description": "Action name from actions_search whose invoke_tool is " + invokeToolName(risk) + ".", "pattern": actionName.String()},
		"targets":         targetsSchema(" The action's max_targets, if any, applies; a job with more targets is rejected."),
		"expected_count":  expectedCountSchema(),
		"reason":          reasonSchema(),
		"params":          map[string]any{"type": "object", "description": "Signed action parameters, as input_schema.params from actions_search with include_schema."},
		"wait_seconds":    waitSchema(cfg),
		"batch_size":      map[string]any{"type": "integer", "description": "Hosts per batch; may only lower the action's effective_batch_size.", "minimum": 1, "maximum": cfg.BatchSize},
		"max_failures":    map[string]any{"type": "integer", "description": "Stop after failures exceed this limit; may only lower the action's effective_max_failures.", "minimum": 0, "maximum": cfg.MaxFailures},
		"response_format": formatSchema(),
		"grouping":        groupingSchema("exact"),
	}
	for _, name := range []string{"match", "exclude", "tail", "head", "count"} {
		props[name], _ = filterSchema(name)
	}
	return ToolDefinition{Name: invokeToolName(risk), Description: "Run one " + risk + "-risk catalog action found with actions_search. Pass its name in action, with the arguments the action takes: targets, reason, params, and optionally expected_count, wait_seconds, batch_size, max_failures, response_format, grouping and the output filters listed in its filters. The call is refused unless the action's current risk is " + risk + "." + toolInstructions, Annotations: annotations, InputSchema: map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": props, "required": []string{"action", "targets", "reason"}, "additionalProperties": false,
	}}
}
