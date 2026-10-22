package flareapi

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"time"
)

const paginationBody = "body"

func (client *Client) Collect(ctx context.Context, operation Operation, input Request, maxPages int, delay time.Duration) (*Response, error) {
	if operation.PageIn == "" {
		return nil, fmt.Errorf("%s does not declare cursor pagination", operation.ID)
	}
	if maxPages <= 0 || delay < 0 {
		return nil, fmt.Errorf("max pages must be positive and page delay non-negative")
	}
	input.Parameters = maps.Clone(input.Parameters)
	if input.Parameters == nil {
		input.Parameters = make(map[string]json.RawMessage)
	}
	if operation.PageIn == paginationBody {
		if _, err := requestBodyObject(input.Body); err != nil {
			return nil, err
		}
	}
	items := make([]json.RawMessage, 0)
	seen := make(map[string]bool)
	for pageNumber := 0; pageNumber < maxPages; pageNumber++ {
		response, err := client.Call(ctx, operation, input)
		if err != nil {
			return nil, err
		}
		page, err := decodePage(response.Body)
		if err != nil {
			return nil, err
		}
		items = append(items, page.items...)
		next := page.next
		if next == "" || pageNumber+1 == maxPages {
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
		if err := advanceCursor(&input, operation.PageIn, next); err != nil {
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
	next     string
}

func decodePage(data []byte) (cursorPage, error) {
	var page cursorPage
	if err := json.Unmarshal(data, &page.envelope); err != nil {
		return page, fmt.Errorf("decode paginated response: %w", err)
	}
	if err := json.Unmarshal(page.envelope["items"], &page.items); err != nil {
		return page, fmt.Errorf("paginated response has no items array: %w", err)
	}
	if raw := page.envelope["next"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &page.next); err != nil {
			return page, fmt.Errorf("decode next cursor: %w", err)
		}
	}
	return page, nil
}

func requestBodyObject(data []byte) (map[string]json.RawMessage, error) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(data, &body); err != nil || body == nil {
		return nil, fmt.Errorf("pagination requires a JSON object request body")
	}
	return body, nil
}

func advanceCursor(input *Request, location, next string) error {
	cursor, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if location != paginationBody {
		input.Parameters["from"] = cursor
		return nil
	}
	body, err := requestBodyObject(input.Body)
	if err != nil {
		return err
	}
	body["from"] = cursor
	input.Body, err = json.Marshal(body)
	return err
}
