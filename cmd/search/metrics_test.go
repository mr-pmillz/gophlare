package search

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mr-pmillz/gophlare/metrics"
	"github.com/mr-pmillz/gophlare/phlare"
)

// TestReportMetricsWritesArtifact covers the reporting half of the fatal path.
// fatalf itself calls utils.LogFatalf (os.Exit), so only reportMetrics is
// exercised here — that is the part that must run before the process dies.
func TestReportMetricsWritesArtifact(t *testing.T) {
	metrics.Default().Record(metrics.Call{
		Endpoint: metrics.EndpointGlobalEventsSearch,
		Entity:   "example.com",
		Status:   200,
	})

	dir := t.TempDir()
	reportMetrics(&phlare.Options{
		Metrics:      true,
		MonthlyQuota: metrics.DefaultMonthlyQuota,
		Output:       dir,
		Version:      "v0.0.0-test",
	})

	if _, err := os.Stat(filepath.Join(dir, metrics.MetricsJSONFileName)); err != nil {
		t.Fatalf("expected %s in the output dir: %v", metrics.MetricsJSONFileName, err)
	}
}

// TestReportMetricsDisabledWritesNothing confirms --metrics gates the report
// while collection stays unconditional.
func TestReportMetricsDisabledWritesNothing(t *testing.T) {
	dir := t.TempDir()

	reportMetrics(&phlare.Options{
		Metrics:      false,
		MonthlyQuota: metrics.DefaultMonthlyQuota,
		Output:       dir,
	})

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	if len(entries) != 0 {
		t.Errorf("output dir has %d entries, want 0 when --metrics is unset", len(entries))
	}
}
