package mcp

import "github.com/liubing0806/allowops/internal/gateway/job"

func fixedTools(cfg job.Config) []ToolDefinition {
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
		{Name: "jobs_get", Description: "Read a job summary. With host, read lossless paginated host output as data_base64 with encoding=base64 (default); pass next_offset as offset to continue. With host and encoding=text, read the page as UTF-8 text in data; next_offset stops at a complete character, and output that is not valid UTF-8 returns ENCODING_NOT_TEXT, after which read it with encoding=base64. Summary counts cover all tasks; groups and offline_hosts cover the current page. P6 summaries may already be truncated; the truncated marker is preserved. Composite action output requires step_index and is read one step at a time. Output additionally requires view_output authorization.", Annotations: ToolAnnotations{ReadOnlyHint: true}, InputSchema: object(map[string]any{"job_id": jobID(), "host": text("Hostname whose complete output is requested."), "wait_seconds": waitSchema(cfg), "response_format": formatSchema(), "next_cursor": cursor(), "stream": map[string]any{"type": "string", "description": "Host output stream.", "enum": []string{"stdout", "stderr"}, "default": "stdout"}, "step_index": outputStepSchema(), "offset": map[string]any{"type": "integer", "description": "Byte offset in stored output; use next_offset to continue.", "minimum": 0, "maximum": uint64(^uint64(0))}, "encoding": map[string]any{"type": "string", "description": "Host output encoding: base64 returns data_base64; text returns UTF-8 data or ENCODING_NOT_TEXT. Only with host.", "enum": []string{"base64", "text"}, "default": "base64"}}, "job_id")},
		{Name: "jobs_list", Description: "List recent jobs belonging to the current authenticated service account or CLI user.", Annotations: ToolAnnotations{ReadOnlyHint: true}, InputSchema: object(map[string]any{"next_cursor": cursor()})},
		{Name: "jobs_cancel", Description: "Cancel a job: stop future batches and terminate running task process groups. Service accounts may only cancel their own jobs; users require execution authorization on every job host.", InputSchema: object(map[string]any{"job_id": jobID()}, "job_id")},
	}
	for i := range tools {
		tools[i].Description += toolInstructions
	}
	return tools
}
