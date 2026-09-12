package metrics

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// renderRecorder renders a recorder's report to a string with color disabled.
func renderRecorder(t *testing.T, r *Recorder, monthlyQuota int) string {
	t.Helper()
	var buf bytes.Buffer
	if err := r.Snapshot(monthlyQuota).Render(&buf, false); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	return buf.String()
}

func TestRenderShowsUnknownQuotaAsQuestionMark(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointBulkAccounts, Entity: EntityBulkEmails, Status: 200})

	out := renderRecorder(t, r, 10000)

	if !strings.Contains(out, string(EndpointBulkAccounts)) {
		t.Fatalf("report is missing the endpoint row:\n%s", out)
	}
	if !regexp.MustCompile(`by_accounts\s+\?`).MatchString(out) {
		t.Errorf("bulk-accounts billing should render as %q in the BILLS column:\n%s", "?", out)
	}
	if !strings.Contains(out, "undocumented") {
		t.Errorf("report should explain the undocumented billing:\n%s", out)
	}
}

func TestRenderDistinguishesFreeFromUnknown(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointASTPCredentialsSearch, Entity: "example.com", Status: 200})

	out := renderRecorder(t, r, 10000)

	if !strings.Contains(out, quotaFreeCell) {
		t.Errorf("a documented-free endpoint should render %q in the entity QUOTA column:\n%s", quotaFreeCell, out)
	}
	if strings.Contains(out, "undocumented") {
		t.Errorf("no undocumented endpoint was used, so no such note belongs:\n%s", out)
	}
}

// TestRenderWithoutQuotaHeaderMakesNoClaim is the honesty guard: when Flare
// never returned the quota header, the report must say so rather than print a
// plausible-looking zero or a fabricated remaining count.
func TestRenderWithoutQuotaHeaderMakesNoClaim(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointASTPCookiesSearch, Entity: "example.com", Status: 200})

	out := renderRecorder(t, r, 10000)

	if !strings.Contains(out, "no quota header") {
		t.Errorf("report should state the header was absent:\n%s", out)
	}
	if strings.Contains(out, "Remaining") {
		t.Errorf("report must not show a Remaining figure it never observed:\n%s", out)
	}
	if strings.Contains(out, "of monthly quota used") {
		t.Errorf("report must not compute a usage percentage without a header:\n%s", out)
	}
}

func TestRenderExplainsCountedExceedingObserved(t *testing.T) {
	r := NewRecorder()
	// Three global searches, but Flare only decremented the allocation by one:
	// the first request is outside the interval; repeated searches may be free.
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Header: remainingHeader("9000")})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Header: remainingHeader("9000")})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Header: remainingHeader("8999")})

	out := renderRecorder(t, r, 10000)

	if !strings.Contains(out, "within 10 minutes") {
		t.Errorf("report should explain the counted/observed gap:\n%s", out)
	}
	if !strings.Contains(out, "excludes usage before the first header") {
		t.Errorf("report should explain the missing baseline:\n%s", out)
	}
	if !strings.Contains(out, "2 above observed") {
		t.Errorf("report should quantify the gap as 2:\n%s", out)
	}
}

func TestRenderNoCallsAtAll(t *testing.T) {
	out := renderRecorder(t, NewRecorder(), 10000)

	if !strings.Contains(out, "no Flare API calls were made") {
		t.Errorf("report should state that no calls happened:\n%s", out)
	}
}

func TestRenderIncludesEntityBreakdown(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "zeta.com", Status: 200})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "alpha.com", Status: 200})
	r.Record(Call{Endpoint: EndpointActivityByID, Entity: "alpha.com", Status: 200})

	out := renderRecorder(t, r, 10000)

	for _, want := range []string{"BY ENTITY", "alpha.com", "zeta.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	// alpha.com sorts before zeta.com, so its row must appear first.
	if strings.Index(out, "alpha.com") > strings.Index(out, "zeta.com") {
		t.Errorf("entities should be sorted, alpha.com before zeta.com:\n%s", out)
	}
}

func TestReportOnceIsIdempotent(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200})

	var buf bytes.Buffer
	opts := ReportOptions{Enabled: true, MonthlyQuota: 10000, Writer: &buf, Version: "v0.0.0-test"}

	if err := r.ReportOnce(opts); err != nil {
		t.Fatalf("first ReportOnce() error = %v", err)
	}
	first := buf.Len()
	if first == 0 {
		t.Fatal("first ReportOnce() wrote nothing")
	}

	if err := r.ReportOnce(opts); err != nil {
		t.Fatalf("second ReportOnce() error = %v", err)
	}
	if buf.Len() != first {
		t.Errorf("second ReportOnce wrote %d extra bytes, want 0", buf.Len()-first)
	}
}

func TestReportOnceDisabledWritesNothing(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200})

	dir := t.TempDir()
	var buf bytes.Buffer
	if err := r.ReportOnce(ReportOptions{Enabled: false, MonthlyQuota: 10000, Writer: &buf, OutputDir: dir}); err != nil {
		t.Fatalf("ReportOnce() error = %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("disabled ReportOnce wrote %d bytes, want 0", buf.Len())
	}
	if _, err := os.Stat(filepath.Join(dir, MetricsJSONFileName)); !os.IsNotExist(err) {
		t.Error("disabled ReportOnce should not write the JSON artifact")
	}
}

func TestNilRecorderReportOnceIsSafe(t *testing.T) {
	var r *Recorder

	if err := r.ReportOnce(ReportOptions{Enabled: true, MonthlyQuota: 10000}); err != nil {
		t.Errorf("nil recorder ReportOnce() error = %v, want nil", err)
	}
}

func TestReportOnceWritesJSONArtifact(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200, Header: remainingHeader("9000")})
	r.Record(Call{Endpoint: EndpointBulkAccounts, Entity: EntityBulkEmails, Status: 200})

	dir := t.TempDir()
	var buf bytes.Buffer
	if err := r.ReportOnce(ReportOptions{
		Enabled: true, MonthlyQuota: 10000, OutputDir: dir, Version: "v0.0.0-test", Writer: &buf,
	}); err != nil {
		t.Fatalf("ReportOnce() error = %v", err)
	}

	path := filepath.Join(dir, MetricsJSONFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var got Snapshot
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("artifact is not valid Snapshot JSON: %v", err)
	}
	if got.Totals.Calls != 2 {
		t.Errorf("Totals.Calls = %d, want 2", got.Totals.Calls)
	}
	if got.Version != "v0.0.0-test" {
		t.Errorf("Version = %q, want v0.0.0-test", got.Version)
	}
	if got.MonthlyQuota != 10000 {
		t.Errorf("MonthlyQuota = %d, want 10000", got.MonthlyQuota)
	}
	if !strings.Contains(buf.String(), MetricsJSONFileName) {
		t.Errorf("report should name the artifact it wrote:\n%s", buf.String())
	}
}

func TestReportOnceMissingOutputDirReturnsError(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200})

	var buf bytes.Buffer
	err := r.ReportOnce(ReportOptions{
		Enabled: true, MonthlyQuota: 10000, Writer: &buf,
		OutputDir: filepath.Join(t.TempDir(), "does-not-exist"),
	})

	if err == nil {
		t.Error("ReportOnce() error = nil, want an error for an unwritable output dir")
	}
}

func TestHumanInt(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want string
	}{
		{"zero", 0, "0"},
		{"single digit", 7, "7"},
		{"three digits stay bare", 999, "999"},
		{"four digits get a separator", 1000, "1,000"},
		{"default monthly quota", 10000, "10,000"},
		{"six digits", 123456, "123,456"},
		{"seven digits", 1234567, "1,234,567"},
		{"negative", -8213, "-8,213"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := humanInt(tt.in); got != tt.want {
				t.Errorf("humanInt(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestQuotaCell(t *testing.T) {
	tests := []struct {
		name  string
		units int
		want  string
	}{
		{"undocumented billing", QuotaUnitsUnknown, quotaUnknownCell},
		{"documented free", 0, quotaFreeCell},
		{"billed units", 61, "61"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := quotaCell(tt.units); got != tt.want {
				t.Errorf("quotaCell(%d) = %q, want %q", tt.units, got, tt.want)
			}
		})
	}
}

// TestRenderColorizedStillContainsData guards against the color wrapper eating
// content when colorize is on.
func TestRenderColorizedStillContainsData(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Entity: "example.com", Status: 200})

	var buf bytes.Buffer
	if err := r.Snapshot(10000).Render(&buf, true); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	out := buf.String()
	for _, want := range []string{"GLOBAL SEARCH QUOTA", "example.com", string(EndpointGlobalEventsSearch)} {
		if !strings.Contains(out, want) {
			t.Errorf("colorized report missing %q:\n%s", want, out)
		}
	}
}

func TestRenderSingleHeaderDoesNotClaimZeroConsumption(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Status: 200, Header: remainingHeader("9999")})
	out := renderRecorder(t, r, 10000)
	if !strings.Contains(out, "only one quota observation; no baseline") || strings.Contains(out, "Consumed this run") {
		t.Fatalf("report claims consumption without a baseline:\n%s", out)
	}
}

func TestRenderQuotaIncreaseAndAllocationMismatch(t *testing.T) {
	r := NewRecorder()
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Header: remainingHeader("99")})
	r.Record(Call{Endpoint: EndpointGlobalEventsSearch, Header: remainingHeader("20000")})
	out := renderRecorder(t, r, 10000)
	if !strings.Contains(out, "quota increased") || !strings.Contains(out, "exceeds configured monthly quota") {
		t.Fatalf("missing quota state warnings:\n%s", out)
	}
	if strings.Contains(out, "-100.0%") {
		t.Fatalf("negative monthly usage:\n%s", out)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestReportPreservesArtifactAndErrorOnBrokenWriter(t *testing.T) {
	r := NewRecorder()
	dir := t.TempDir()
	wantErr := errors.New("broken pipe")
	opts := ReportOptions{Enabled: true, OutputDir: dir, Writer: failingWriter{wantErr}}
	for range 2 {
		if err := r.ReportOnce(opts); !errors.Is(err, wantErr) {
			t.Fatalf("ReportOnce error = %v, want %v", err, wantErr)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, MetricsJSONFileName)); err != nil {
		t.Fatalf("artifact lost when output failed: %v", err)
	}
}
