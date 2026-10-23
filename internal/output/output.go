package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"

	"github.com/rivo/uniseg"
)

const valueColumn = "value"

type Options struct {
	Format  string
	Columns []string
	Wide    bool
	RootKey string
}

func Write(writer io.Writer, data []byte, options Options) error {
	if len(bytes.TrimSpace(data)) == 0 {
		data = []byte("null")
	}
	if !json.Valid(data) {
		return fmt.Errorf("response is not JSON; use --output-file for downloads or text responses")
	}
	if options.Format == "json" {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err != nil {
			return err
		}
		pretty.WriteByte('\n')
		_, err := writer.Write(pretty.Bytes())
		return err
	}
	if options.Format != "table" {
		return fmt.Errorf("unsupported format %q (use table or json)", options.Format)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if envelope, ok := value.(map[string]any); ok && options.RootKey != "" {
		if wrapped, exists := envelope[options.RootKey]; exists {
			value = wrapped
		}
	}
	return writeTable(writer, value, options)
}

func writeTable(writer io.Writer, value any, options Options) error {
	rows := records(value)
	if len(rows) == 0 {
		_, err := fmt.Fprintln(writer, "No results.")
		return err
	}
	columns := options.Columns
	if len(columns) == 0 {
		columns = defaultColumns(rows)
	}
	widths := make([]int, len(columns))
	cells := make([][]string, len(rows))
	headers := make([]string, len(columns))
	for columnIndex, column := range columns {
		headers[columnIndex] = strings.ToUpper(strings.NewReplacer("_", " ", ".", " ").Replace(column))
	}
	prepareTableRow(headers, widths, options.Wide)
	for rowIndex, row := range rows {
		rowCells := make([]string, len(columns))
		for columnIndex, column := range columns {
			rowCells[columnIndex] = display(lookup(row, column))
		}
		prepareTableRow(rowCells, widths, options.Wide)
		cells[rowIndex] = rowCells
	}
	var result strings.Builder
	border(&result, widths, "┌", "┬", "┐")
	writeTableRow(&result, headers, widths)
	border(&result, widths, "├", "┼", "┤")
	for _, row := range cells {
		writeTableRow(&result, row, widths)
	}
	border(&result, widths, "└", "┴", "┘")
	fmt.Fprintf(&result, "%d result(s)\n", len(rows))
	_, err := io.WriteString(writer, result.String())
	return err
}

func prepareTableRow(cells []string, widths []int, wide bool) {
	for columnIndex, cell := range cells {
		cell = sanitize(cell)
		if !wide {
			cell = truncate(cell, 48)
		}
		cells[columnIndex] = cell
		widths[columnIndex] = max(widths[columnIndex], uniseg.StringWidth(cell))
	}
}

func writeTableRow(writer *strings.Builder, cells []string, widths []int) {
	writer.WriteString("│")
	for columnIndex, cell := range cells {
		writer.WriteString(" " + cell + strings.Repeat(" ", widths[columnIndex]-uniseg.StringWidth(cell)+1) + "│")
	}
	writer.WriteByte('\n')
}

func records(value any) []map[string]any {
	if object, ok := value.(map[string]any); ok {
		for _, key := range []string{"items", "results", "data"} {
			if items, ok := object[key].([]any); ok {
				return records(items)
			}
		}
		if len(object) == 0 {
			return nil
		}
		return []map[string]any{object}
	}
	if items, ok := value.([]any); ok {
		rows := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if object, ok := item.(map[string]any); ok {
				rows = append(rows, object)
			} else {
				rows = append(rows, map[string]any{valueColumn: item})
			}
		}
		return rows
	}
	if value == nil {
		return nil
	}
	return []map[string]any{{valueColumn: value}}
}

func defaultColumns(rows []map[string]any) []string {
	available := make(map[string]bool)
	for _, row := range rows {
		for key := range row {
			available[key] = true
		}
	}
	preferred := []string{"id", "name", "type", valueColumn, "data", "is_disabled", "group_id", "frequency", "feed_target_id", "start_at", "status", "email", "tenant_id", "organization_id", "created_at", "title"}
	if available["operation_id"] {
		preferred = []string{"version", "operation_id", "method", "path"}
	}
	if available["metadata"] {
		preferred = []string{"metadata.uid", "metadata.type", "metadata.severity", "metadata.estimated_created_at", "title", "name", "id"}
	}
	columns := make([]string, 0, 8)
	for _, key := range preferred {
		for _, row := range rows {
			if lookup(row, key) != nil {
				columns = append(columns, key)
				break
			}
		}
		if len(columns) == 8 {
			return columns
		}
	}
	if len(columns) > 0 {
		return columns
	}
	for key := range available {
		columns = append(columns, key)
	}
	slices.Sort(columns)
	return columns[:min(len(columns), 8)]
}

func lookup(row map[string]any, key string) any {
	var value any = row
	for segment := range strings.SplitSeq(key, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[segment]
	}
	return value
}

func display(value any) string {
	if value == nil {
		return "—"
	}
	if text, ok := value.(string); ok {
		return text
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "—"
	}
	return string(encoded)
}

func sanitize(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return ' '
		}
		return character
	}, value)
}

func truncate(value string, width int) string {
	if uniseg.StringWidth(value) <= width {
		return value
	}
	var result strings.Builder
	graphemes := uniseg.NewGraphemes(value)
	used := 0
	for graphemes.Next() {
		cluster := graphemes.Str()
		clusterWidth := uniseg.StringWidth(cluster)
		if used+clusterWidth >= width {
			break
		}
		result.WriteString(cluster)
		used += clusterWidth
	}
	return result.String() + "…"
}

func border(writer *strings.Builder, widths []int, left, middle, right string) {
	writer.WriteString(left)
	for columnIndex, width := range widths {
		if columnIndex > 0 {
			writer.WriteString(middle)
		}
		writer.WriteString(strings.Repeat("─", width+2))
	}
	writer.WriteString(right + "\n")
}
