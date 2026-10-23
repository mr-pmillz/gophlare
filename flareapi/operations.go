package flareapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
)

type Parameter struct {
	Name        string `json:"name"`
	In          string `json:"in"`
	Type        string `json:"type"`
	Format      string `json:"format,omitempty"`
	ItemType    string `json:"item_type,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
}

type Operation struct {
	Version      string            `json:"version"`
	ID           string            `json:"operation_id"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Summary      string            `json:"summary,omitempty"`
	Description  string            `json:"description,omitempty"`
	Parameters   []Parameter       `json:"parameters,omitempty"`
	HasBody      bool              `json:"has_body"`
	BodyRequired bool              `json:"body_required"`
	BodySchema   string            `json:"body_schema,omitempty"`
	Deprecated   bool              `json:"deprecated"`
	PageIn       string            `json:"page_in,omitempty"`
	PageCursors  map[string]string `json:"page_cursors,omitempty"`
	ResponseKey  string            `json:"response_key,omitempty"`
	build        func(string, Request, io.Reader) (*http.Request, error)
}

type Request struct {
	Parameters map[string]json.RawMessage
	Body       json.RawMessage
}

func Operations() []Operation {
	result := slices.Clone(operationDefinitions)
	for index := range result {
		result[index].Parameters = slices.Clone(result[index].Parameters)
		result[index].PageCursors = maps.Clone(result[index].PageCursors)
	}
	return result
}

func FindOperation(version, identifier string) (Operation, error) {
	for _, operation := range operationDefinitions {
		if operation.Version == version && operation.ID == identifier {
			operation.Parameters = slices.Clone(operation.Parameters)
			operation.PageCursors = maps.Clone(operation.PageCursors)
			return operation, nil
		}
	}
	return Operation{}, fmt.Errorf("unknown %s operation %q", version, identifier)
}

func (operation Operation) BuildRequest(ctx context.Context, server string, input Request) (*http.Request, error) {
	if operation.build == nil {
		return nil, fmt.Errorf("operation has no generated request builder")
	}
	allowed := make(map[string]bool, len(operation.Parameters))
	for _, parameter := range operation.Parameters {
		allowed[parameter.Name] = true
		value, exists := input.Parameters[parameter.Name]
		if parameter.Required && (!exists || bytes.Equal(bytes.TrimSpace(value), []byte("null"))) {
			return nil, fmt.Errorf("%s requires %s parameter %q", operation.ID, parameter.In, parameter.Name)
		}
	}
	for name := range input.Parameters {
		if !allowed[name] {
			return nil, fmt.Errorf("unknown parameter %q for %s", name, operation.ID)
		}
	}
	if operation.BodyRequired && len(input.Body) == 0 {
		return nil, fmt.Errorf("%s requires a JSON request body", operation.ID)
	}
	if len(input.Body) > 0 {
		if !operation.HasBody {
			return nil, fmt.Errorf("%s does not accept a request body", operation.ID)
		}
		if !json.Valid(input.Body) {
			return nil, fmt.Errorf("invalid JSON request body")
		}
	}
	var body io.Reader
	if len(input.Body) > 0 {
		body = bytes.NewReader(input.Body)
	}
	request, err := operation.build(strings.TrimRight(server, "/")+"/", input, body)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", operation.ID, err)
	}
	return request.WithContext(ctx), nil
}

func decodeParameter[Value any](parameters map[string]json.RawMessage, name string) (Value, error) {
	var value Value
	if err := json.Unmarshal(parameters[name], &value); err != nil {
		return value, fmt.Errorf("invalid %s: %w", name, err)
	}
	return value, nil
}

func decodeParameters[Value any](parameters map[string]json.RawMessage) (*Value, error) {
	encoded, err := json.Marshal(parameters)
	if err != nil {
		return nil, err
	}
	var value Value
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	return &value, nil
}
