package search

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mr-pmillz/gophlare/metrics"
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// TestReportMetricsWritesArtifact covers the reporting half of the fatal path.
// fatalf itself calls utils.LogFatalf (os.Exit), so only reportMetrics is
// exercised here — that is the part that must run before the process dies.
func TestReportMetricsWritesArtifact(t *testing.T) {
	recorder := metrics.NewRecorder()
	recorder.Record(metrics.Call{
		Endpoint: metrics.EndpointGlobalEventsSearch,
		Entity:   "example.com",
		Status:   200,
	})

	dir := t.TempDir()
	reportMetrics(&phlare.Options{
		Metrics:         true,
		MetricsRecorder: recorder,
		MonthlyQuota:    metrics.DefaultMonthlyQuota,
		Output:          dir,
		Version:         "v0.0.0-test",
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

func TestSearchReportsToConfiguredOutputForEachInvocation(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.Set("API_KEYS.FLARE_API", "test-key")
	viper.Set("API_KEYS.FLARE_TENANT_ID", 1)
	viper.Set("DOMAINS", "example.com")
	viper.Set("METRICS", true)
	viper.Set("MONTHLY_QUOTA", 12345)
	for range 2 {
		dir := t.TempDir()
		viper.Set("OUTPUT", dir)
		cmd := &cobra.Command{Use: "search", Version: "test", Run: Command.Run}
		configureCommand(cmd)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, metrics.MetricsJSONFileName)); err != nil {
			t.Fatalf("report missing from configured output: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(dir, metrics.MetricsJSONFileName))
		if err != nil {
			t.Fatal(err)
		}
		var report metrics.Snapshot
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if report.MonthlyQuota != 12345 || report.Totals.Calls != 0 {
			t.Fatalf("configured quota or invocation isolation failed: %+v", report)
		}
	}
}
