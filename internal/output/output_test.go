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
