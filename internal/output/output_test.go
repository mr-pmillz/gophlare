package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{"groups", `{"items":[{"id":7,"name":"Production"}]}`, "Production"},
		{"identifiers", `{"items":[{"id":1,"type":"domain","data":{"fqdn":"example.test"},"is_disabled":false}]}`, "false"},
		{"alerts", `[{"id":2,"name":"Email alert","frequency":60,"type":"email"}]`, "FREQUENCY"},
		{"large IDs", `[{"id":9007199254740993}]`, "9007199254740993"},
		{"unicode", `[{"name":"東京 🔥"}]`, "東京 🔥"},
		{"empty", `{"items":[]}`, "No results."},
		{"empty body", "", "No results."},
		{"boolean", "false", "false"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var buffer bytes.Buffer
			if err := Write(&buffer, []byte(test.body), Options{Format: "table"}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buffer.String(), test.want) {
				t.Errorf("output missing %q:\n%s", test.want, buffer.String())
			}
		})
	}
}

func TestWriteTableLayout(test *testing.T) {
	test.Parallel()
	for _, fixture := range []struct {
		name    string
		body    string
		columns []string
		want    string
	}{
		{
			name: "empty",
			body: `[]`,
			want: "No results.\n",
		},
		{
			name: "single row",
			body: `[{"id":7,"name":"Production"}]`,
			want: "┌────┬────────────┐\n" +
				"│ ID │ NAME       │\n" +
				"├────┼────────────┤\n" +
				"│ 7  │ Production │\n" +
				"└────┴────────────┘\n" +
				"1 result(s)\n",
		},
		{
			name: "last row determines widths",
			body: `[{"id":7,"name":"Dev"},{"id":1001,"name":"Production"}]`,
			want: "┌──────┬────────────┐\n" +
				"│ ID   │ NAME       │\n" +
				"├──────┼────────────┤\n" +
				"│ 7    │ Dev        │\n" +
				"│ 1001 │ Production │\n" +
				"└──────┴────────────┘\n" +
				"2 result(s)\n",
		},
		{
			name:    "header determines width",
			body:    `[{"identifier":"x"}]`,
			columns: []string{"identifier"},
			want: "┌────────────┐\n" +
				"│ IDENTIFIER │\n" +
				"├────────────┤\n" +
				"│ x          │\n" +
				"└────────────┘\n" +
				"1 result(s)\n",
		},
		{
			name: "unicode display width",
			body: `[{"name":"東京 🔥"},{"name":"e\u0301"}]`,
			want: "┌─────────┐\n" +
				"│ NAME    │\n" +
				"├─────────┤\n" +
				"│ 東京 🔥 │\n" +
				"│ e\u0301       │\n" +
				"└─────────┘\n" +
				"2 result(s)\n",
		},
		{
			name: "no columns",
			body: `[{}]`,
			want: "┌┐\n│\n├┤\n│\n└┘\n1 result(s)\n",
		},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			test.Parallel()
			var buffer bytes.Buffer
			if err := Write(&buffer, []byte(fixture.body), Options{Format: "table", Columns: fixture.columns}); err != nil {
				test.Fatal(err)
			}
			if buffer.String() != fixture.want {
				test.Fatalf("table layout changed:\ngot:\n%swant:\n%s", buffer.String(), fixture.want)
			}
		})
	}
}

func TestWriteTableCellFormatting(test *testing.T) {
	test.Parallel()
	column := "\x1b" + strings.Repeat("x", 60) + "\n"
	value := "\x1b" + strings.Repeat("y", 60) + "\n"
	body, err := json.Marshal([]map[string]string{{column: value}})
	if err != nil {
		test.Fatal(err)
	}
	for _, fixture := range []struct {
		name   string
		wide   bool
		header string
		cell   string
	}{
		{"truncated", false, " " + strings.Repeat("X", 46) + "…", " " + strings.Repeat("y", 46) + "…"},
		{"wide", true, " " + strings.Repeat("X", 60) + " ", " " + strings.Repeat("y", 60) + " "},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			test.Parallel()
			var buffer bytes.Buffer
			if err := Write(&buffer, body, Options{Format: "table", Columns: []string{column}, Wide: fixture.wide}); err != nil {
				test.Fatal(err)
			}
			lines := strings.Split(buffer.String(), "\n")
			if len(lines) != 7 {
				test.Fatalf("unexpected number of table lines: %q", buffer.String())
			}
			if lines[1] != "│ "+fixture.header+" │" || lines[3] != "│ "+fixture.cell+" │" {
				test.Fatalf("header or cell formatting changed: %q", buffer.String())
			}
		})
	}
}

func TestWriteJSONAndTableSafety(t *testing.T) {
	t.Parallel()
	body := []byte(`{"items":[{"id":9007199254740993,"name":"\u001b[31mred\nname","metadata":{"severity":"high"}}],"next":"opaque"}`)
	var buffer bytes.Buffer
	if err := Write(&buffer, body, Options{Format: "json"}); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(buffer.Bytes()) || !strings.Contains(buffer.String(), "9007199254740993") || !strings.Contains(buffer.String(), "opaque") {
		t.Fatalf("JSON was altered: %s", buffer.String())
	}
	buffer.Reset()
	if err := Write(&buffer, body, Options{Format: "table", Columns: []string{"name", "metadata.severity"}}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(buffer.String(), '\x1b') || !strings.Contains(buffer.String(), "high") || !strings.Contains(buffer.String(), "┌") {
		t.Fatalf("unsafe or missing table content: %q", buffer.String())
	}
	if err := Write(&buffer, []byte("binary"), Options{Format: "json"}); err == nil {
		t.Fatal("non-JSON response should require a file")
	}
	if err := Write(failingWriter{}, body, Options{Format: "table"}); err == nil {
		t.Fatal("writer failure lost")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture write error")
}

func TestWriteResourceEnvelopes(test *testing.T) {
	test.Parallel()
	for _, fixture := range []struct {
		name  string
		body  string
		key   string
		want  string
		count string
	}{
		{"group object", `{"assets_groups":{"id":7,"name":"Production"}}`, "assets_groups", "Production", "1 result(s)"},
		{"group array", `{"assets_groups":[{"id":7,"name":"Production"},{"id":8,"name":"Staging"}]}`, "assets_groups", "Staging", "2 result(s)"},
		{"alert object", `{"alerts":{"id":9,"name":"Production"}}`, "alerts", "Production", "1 result(s)"},
		{"alert array", `{"alerts":[{"id":9,"name":"Production"},{"id":10,"name":"Staging"}]}`, "alerts", "Staging", "2 result(s)"},
		{"empty array", `{"alerts":[]}`, "alerts", "No results.", ""},
		{"empty object", `{"assets_groups":{}}`, "assets_groups", "No results.", ""},
		{"null", `{"alerts":null}`, "alerts", "No results.", ""},
		{"unwrapped", `[{"id":7,"name":"Production"}]`, "assets_groups", "Production", "1 result(s)"},
		{"alternate envelope", `{"items":[{"id":7,"name":"Production"}]}`, "assets_groups", "Production", "1 result(s)"},
		{"nested field not envelope", `{"id":7,"name":"Production","alerts":[{"id":9,"name":"Hidden"}]}`, "", "Production", "1 result(s)"},
	} {
		test.Run(fixture.name, func(test *testing.T) {
			for _, columns := range [][]string{nil, {"id", "name"}} {
				var buffer bytes.Buffer
				if err := Write(&buffer, []byte(fixture.body), Options{Format: "table", RootKey: fixture.key, Columns: columns}); err != nil {
					test.Fatal(err)
				}
				if !strings.Contains(buffer.String(), fixture.want) || !strings.Contains(buffer.String(), fixture.count) {
					test.Fatalf("columns=%v: missing rows in output:\n%s", columns, buffer.String())
				}
			}
			var formatted, compact bytes.Buffer
			if err := Write(&formatted, []byte(fixture.body), Options{Format: "json", RootKey: fixture.key}); err != nil {
				test.Fatal(err)
			}
			if err := json.Compact(&compact, formatted.Bytes()); err != nil || compact.String() != fixture.body {
				test.Fatalf("JSON envelope changed: %s, %v", formatted.String(), err)
			}
		})
	}
}
