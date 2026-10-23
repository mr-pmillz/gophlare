package flareapi

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"
)

const paginationBody = "body"

func (client *Client) Collect(ctx context.Context, operation Operation, input Request, maxPages int, delay time.Duration) (*Response, error) {
	if operation.PageIn == "" || len(operation.PageCursors) == 0 {
		return nil, fmt.Errorf("%s does not declare cursor pagination", operation.ID)
	}
	if maxPages <= 0 || delay < 0 {
		return nil, fmt.Errorf("max pages must be positive and page delay non-negative")
	}
	input.Parameters = maps.Clone(input.Parameters)
	if input.Parameters == nil {
		input.Parameters = make(map[string]json.RawMessage)
	}
	seen, err := operation.initialCursors(input)
	if err != nil {
		return nil, err
	}
	items := make([]json.RawMessage, 0)
	for pageNumber := range maxPages {
		response, err := client.Call(ctx, operation, input)
		if err != nil {
			return nil, err
		}
		page, err := decodePage(operation, response.Body)
		if err != nil {
			return nil, err
		}
		items = append(items, page.items...)
		next := page.next
		if next.value == "" || pageNumber+1 == maxPages {
			page.envelope["items"], err = json.Marshal(items)
			if err != nil {
				return nil, err
			}
			response.Body, err = json.Marshal(page.envelope)
			return response, err
		}
		if seen[next] {
			return nil, fmt.Errorf("flare returned a repeated pagination cursor")
		}
		seen[next] = true
		if err := advanceCursor(&input, operation, next); err != nil {
			return nil, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("no pages fetched")
}

type cursorPage struct {
	envelope map[string]json.RawMessage
	items    []json.RawMessage
	next     pageCursor
}

type pageCursor struct {
	field string
	value string
}

func (operation Operation) NextCursor(data []byte) (string, string, error) {
	if len(operation.PageCursors) == 0 {
		return "", "", nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", "", fmt.Errorf("decode paginated response: %w", err)
	}
	cursor, err := operation.nextCursor(envelope)
	return cursor.field, cursor.value, err
}

func (operation Operation) nextCursor(envelope map[string]json.RawMessage) (pageCursor, error) {
	for _, field := range slices.Sorted(maps.Keys(operation.PageCursors)) {
		if raw, exists := envelope[field]; exists {
			cursor := pageCursor{field: field}
			if err := json.Unmarshal(raw, &cursor.value); err != nil {
				return cursor, fmt.Errorf("decode %s cursor: %w", field, err)
			}
			return cursor, nil
		}
	}
	return pageCursor{}, nil
}

func decodePage(operation Operation, data []byte) (cursorPage, error) {
	var page cursorPage
	if err := json.Unmarshal(data, &page.envelope); err != nil {
		return page, fmt.Errorf("decode paginated response: %w", err)
	}
	if err := json.Unmarshal(page.envelope["items"], &page.items); err != nil {
		return page, fmt.Errorf("paginated response has no items array: %w", err)
	}
	var err error
	page.next, err = operation.nextCursor(page.envelope)
	return page, err
}

func requestBodyObject(data []byte) (map[string]json.RawMessage, error) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(data, &body); err != nil || body == nil {
		return nil, fmt.Errorf("pagination requires a JSON object request body")
	}
	return body, nil
}

func (operation Operation) requestCursors(input Request) (map[string]json.RawMessage, error) {
	if operation.PageIn == paginationBody {
		return requestBodyObject(input.Body)
	}
	return input.Parameters, nil
}

func (operation Operation) initialCursors(input Request) (map[pageCursor]bool, error) {
	cursors, err := operation.requestCursors(input)
	if err != nil {
		return nil, err
	}
	seen := make(map[pageCursor]bool)
	for field, parameter := range operation.PageCursors {
		var value string
		if raw := cursors[parameter]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, fmt.Errorf("decode %s cursor: %w", parameter, err)
			}
		}
		if value != "" {
			seen[pageCursor{field: field, value: value}] = true
		}
	}
	return seen, nil
}

func advanceCursor(input *Request, operation Operation, next pageCursor) error {
	cursor, err := json.Marshal(next.value)
	if err != nil {
		return err
	}
	parameters, err := operation.requestCursors(*input)
	if err != nil {
		return err
	}
	for _, parameter := range operation.PageCursors {
		delete(parameters, parameter)
	}
	parameters[operation.PageCursors[next.field]] = cursor
	if operation.PageIn != paginationBody {
		return nil
	}
	input.Body, err = json.Marshal(parameters)
	return err
}
