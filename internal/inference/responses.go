package inference

import "encoding/json"

func supportedAdapter(adapter string) bool {
	return adapter == "openai-chat" || adapter == "openai-responses"
}

// Keep the legacy Chat schema stable; Responses constrains every existing enum
// and function-dependent nullable value before the unchanged local validators.
func responsesSchema(functions []Function) map[string]any {
	schema := resultSchema()
	p := schema["properties"].(map[string]any)
	enum := func(values ...string) any { return map[string]any{"type": "string", "enum": values} }
	p["schema_version"] = enum("1")
	kinds := []string{}
	for _, f := range functions {
		kinds = append(kinds, string(f))
	}
	if len(functions) > 0 && semantic(functions[0]) {
		kinds = append(kinds, "semantic")
	}
	p["kind"] = enum(kinds...)
	p["labels"].(map[string]any)["items"] = enum("access_offer", "news", "rumor", "denial", "research", "direct_evidence", "irrelevant", "relevant", "unknown")
	p["intent"] = enum("", "seller_claim", "report", "negation", "research", "unknown")
	p["roles"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["role"] = enum("claimed_target", "reference", "benign", "unknown", "claimed_infrastructure")
	plan := p["plan"].(map[string]any)["anyOf"].([]any)[0]
	pp := plan.(map[string]any)["properties"].(map[string]any)
	pp["version"], pp["operation"], pp["mode"], pp["entity"] = enum("1"), enum("search"), enum("exact", "fulltext"), enum("observations", "cases", "entities", "observables")
	pp["limit"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 100}
	identity := p["identity"].(map[string]any)["anyOf"].([]any)[0]
	p["plan"], p["identity"] = map[string]any{"type": "null"}, map[string]any{"type": "null"}
	if len(functions) == 1 && functions[0] == "query.plan" {
		p["plan"] = plan
	}
	if len(functions) == 1 && functions[0] == "identity.disambiguate" {
		p["identity"] = identity
	}
	return schema
}

func responsesSchemaForSnapshot(functions []Function, snapshot Snapshot) map[string]any {
	return responsesSchemaForPrompt(functions, snapshot, "2")
}
func responsesSchemaForPrompt(functions []Function, snapshot Snapshot, version string) map[string]any {
	schema := responsesSchema(functions)
	if version == "2" && len(snapshot.Documents) == 0 {
		properties := schema["properties"].(map[string]any)
		for _, name := range []string{"refs", "claims", "entities", "roles"} {
			properties[name].(map[string]any)["maxItems"] = 0
		}
	}
	return schema
}

func decodeResponses(raw []byte, requested string) (GatewayResult, error) {
	var out GatewayResult
	var envelope struct {
		Model      string          `json:"model"`
		Status     string          `json:"status"`
		Error      json.RawMessage `json:"error"`
		Incomplete json.RawMessage `json:"incomplete_details"`
		Usage      *struct {
			Input  *int64 `json:"input_tokens"`
			Output *int64 `json:"output_tokens"`
		} `json:"usage"`
		Output []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	fail := func(code string) (GatewayResult, error) { return out, &GatewayError{code, true, out.Usage == nil, 0} }
	if json.Unmarshal(raw, &envelope) != nil {
		return fail("response_invalid")
	}
	out.Model = envelope.Model
	// Preserve total output usage, including reasoning, even when publication fails.
	if u := envelope.Usage; u != nil && u.Input != nil && u.Output != nil && *u.Input >= 0 && *u.Output >= 0 && *u.Input <= 1<<30 && *u.Output <= 1<<30 {
		out.Usage = &Usage{*u.Input, *u.Output}
	}
	if out.Model != requested {
		return fail("model_changed")
	}
	if envelope.Status != "completed" || (len(envelope.Error) > 0 && string(envelope.Error) != "null") || (len(envelope.Incomplete) > 0 && string(envelope.Incomplete) != "null") {
		return fail("response_incomplete")
	}
	content := ""
	messages := 0
	for _, item := range envelope.Output {
		if item.Type == "reasoning" {
			continue
		}
		if item.Type != "message" || item.Status != "completed" || item.Role != "assistant" || len(item.Content) != 1 || item.Content[0].Type != "output_text" {
			return fail("response_incomplete")
		}
		messages++
		content = item.Content[0].Text
	}
	if messages != 1 {
		return fail("response_invalid")
	}
	if Strict([]byte(content), &out.Result) != nil {
		return fail("response_schema_invalid")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(content), &fields) != nil {
		return fail("response_schema_invalid")
	}
	for _, name := range []string{"schema_version", "kind", "text", "labels", "intent", "claims", "entities", "roles", "identity", "plan", "refs", "limitations"} {
		if _, ok := fields[name]; !ok {
			return fail("response_schema_invalid")
		}
	}
	if out.Usage == nil {
		return fail("usage_missing")
	}
	return out, nil
}
