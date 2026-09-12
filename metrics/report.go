package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
)

// MetricsJSONFileName is the machine-readable report written to the output dir.
const MetricsJSONFileName = "flare-api-metrics.json"

// quotaUnknownCell and quotaFreeCell keep an undocumented cost visually
// distinct from a known-zero one.
const (
	quotaUnknownCell = "?"
	quotaFreeCell    = "—"
)

// ReportOptions configures a single emission of the usage report.
type ReportOptions struct {
	// Enabled mirrors --metrics. Collection is always on; this gates only the
	// report, so a disabled run still leaves a readable Snapshot for SDK users.
	Enabled bool
	// MonthlyQuota is the operator-supplied denominator (--monthly-quota).
	MonthlyQuota int
	// OutputDir receives flare-api-metrics.json. Empty skips the file.
	OutputDir string
	// Version is stamped in the header and the JSON artifact.
	Version string
	// Writer defaults to os.Stdout.
	Writer io.Writer
	// Colorize enables ANSI styling on section headers.
	Colorize bool
}

// ReportOnce renders the usage report at most once for this recorder. Both the
// normal end-of-run path and the fatal-exit path call it, since quota is spent
// even when a run fails; the sync.Once makes the second call free.
func (r *Recorder) ReportOnce(opts ReportOptions) error {
	if r == nil || !opts.Enabled {
		return nil
	}
	r.reported.Do(func() { r.reportErr = r.emit(opts) })
	return r.reportErr
}

// emit renders the report and, when an output dir is set, writes the JSON.
func (r *Recorder) emit(opts ReportOptions) error {
	w := opts.Writer
	if w == nil {
		w = os.Stdout
	}

	snapshot := r.Snapshot(opts.MonthlyQuota)
	snapshot.Version = opts.Version

	// Persist independently of terminal output: a broken pipe must not discard
	// the artifact, and an unwritable directory must not suppress the table.
	var fileErr error
	path := filepath.Join(opts.OutputDir, MetricsJSONFileName)
	if opts.OutputDir != "" {
		fileErr = WriteJSON(snapshot, path)
	}
	renderErr := snapshot.Render(w, opts.Colorize)
	if opts.OutputDir != "" && fileErr == nil && renderErr == nil {
		_, renderErr = fmt.Fprintf(w, "\n metrics written to: %s\n", path)
	}
	return errors.Join(fileErr, renderErr)
}

// WriteJSON persists a snapshot as indented JSON.
func WriteJSON(s Snapshot, path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Flare API metrics: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write Flare API metrics to %s: %w", path, err)
	}
	return nil
}

// Render writes the human-readable usage report.
func (s Snapshot) Render(w io.Writer, colorize bool) error {
	heading := func(text string) string {
		if !colorize {
			return text
		}
		c := color.New(color.FgHiCyan, color.Bold)
		c.EnableColor()
		return c.Sprint(text)
	}

	version := s.Version
	if version == "" {
		version = "gophlare"
	}
	if _, err := fmt.Fprintf(w, "\n %s\n\n", heading(fmt.Sprintf("FLARE API USAGE — %s · %s",
		version, s.Duration.Round(time.Second)))); err != nil {
		return err
	}

	if err := s.renderQuota(w, heading); err != nil {
		return err
	}
	if err := s.renderEndpoints(w, heading); err != nil {
		return err
	}
	if err := s.renderEntities(w, heading); err != nil {
		return err
	}
	return s.renderNotes(w)
}

// renderQuota writes the monthly-quota summary. Every figure derived from the
// response header is omitted rather than zero-filled when the header never
// arrived, so the report cannot imply a quota state it did not observe.
func (s Snapshot) renderQuota(w io.Writer, heading func(string) string) error {
	if _, err := fmt.Fprintf(w, " %s\n", heading("GLOBAL SEARCH QUOTA")); err != nil {
		return err
	}
	// Dot leaders rather than a tabwriter: labels read better left-aligned
	// against right-aligned figures, which tabwriter cannot mix in one block.
	const labelWidth = 30
	var rowErr error
	row := func(label, value, note string) {
		dots := ""
		if pad := labelWidth - len(label); pad > 0 {
			dots = " " + strings.Repeat(".", pad)
		}
		line := fmt.Sprintf("   %s%s %8s  %s", label, dots, value, note)
		if _, err := fmt.Fprintln(w, strings.TrimRight(line, " ")); err != nil && rowErr == nil {
			rowErr = err
		}
	}

	row("Monthly quota", humanInt(s.MonthlyQuota), "(--monthly-quota, operator-supplied)")

	switch {
	case !s.QuotaHeaderSeen:
		row("Observed quota decrease", "n/a", "API returned no quota header this run")
	case s.QuotaIncreased:
		row("Observed quota decrease", "n/a", "quota increased or responses arrived out of order")
	case s.ObservedConsumed == nil:
		row("Observed quota decrease", "n/a", "only one quota observation; no baseline")
	case s.ObservedConsumed != nil:
		row("Observed quota decrease", humanInt(*s.ObservedConsumed),
			"via "+HeaderGlobalSearchesRemaining)
	}

	if s.RemainingLast != nil {
		note := ""
		if s.MonthlyQuota > 0 && *s.RemainingLast <= s.MonthlyQuota {
			used := float64(s.MonthlyQuota-*s.RemainingLast) / float64(s.MonthlyQuota) * 100
			note = fmt.Sprintf("%.1f%% of monthly quota used", used)
		} else {
			note = "exceeds configured monthly quota; verify --monthly-quota"
		}
		row("Remaining", humanInt(*s.RemainingLast), note)
	}

	countedNote := ""
	if s.ObservedConsumed != nil && s.CountedQuotaCalls > *s.ObservedConsumed {
		countedNote = fmt.Sprintf("%d above observed — see note",
			s.CountedQuotaCalls-*s.ObservedConsumed)
	}
	row("Quota-bearing calls counted", humanInt(s.CountedQuotaCalls), countedNote)

	if s.BatchReached > 0 {
		row("Batch limit reached", humanInt(s.BatchReached), "searches truncated by Flare")
	}

	if rowErr != nil {
		return rowErr
	}
	_, err := fmt.Fprintln(w)
	return err
}

// renderEndpoints writes the per-endpoint breakdown.
func (s Snapshot) renderEndpoints(w io.Writer, heading func(string) string) error {
	if len(s.ByEndpoint) == 0 {
		_, err := fmt.Fprintf(w, " %s\n   no Flare API calls were made this run\n\n",
			heading("BY ENDPOINT"))
		return err
	}

	if _, err := fmt.Fprintf(w, " %s\n", heading("BY ENDPOINT")); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "   ENDPOINT\tBILLS\tCALLS\t2xx\t429\t5xx\tRETRIES\tAVG") //nolint:errcheck // flushed below

	for _, e := range s.ByEndpoint {
		fmt.Fprintf(tw, "   %s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n", //nolint:errcheck // flushed below
			e.Endpoint, e.Quota, e.Calls, e.OK, e.RateLimited, e.ServerError, e.Retries,
			e.AvgDuration.Round(time.Millisecond))
	}
	fmt.Fprintf(tw, "   %s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n", //nolint:errcheck // flushed below
		"TOTAL", "", s.Totals.Calls, s.Totals.OK, s.Totals.RateLimited,
		s.Totals.ServerError, s.Totals.Retries, "")

	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}

// renderEntities writes the per-entity breakdown in long format — one row per
// entity/endpoint pair rather than an endpoint-per-column matrix — so the table
// stays readable in a narrow terminal. The entity name prints only on its first
// row to keep the grouping visible.
func (s Snapshot) renderEntities(w io.Writer, heading func(string) string) error {
	if len(s.ByEntity) == 0 {
		return nil
	}

	if _, err := fmt.Fprintf(w, " %s\n", heading("BY ENTITY")); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "   ENTITY\tENDPOINT\tCALLS\tQUOTA") //nolint:errcheck // flushed below

	for _, entity := range s.ByEntity {
		for i, e := range entity.ByEndpoint {
			name := entity.Entity
			if i > 0 {
				name = ""
			}
			fmt.Fprintf(tw, "   %s\t%s\t%d\t%s\n", //nolint:errcheck // flushed below
				name, e.Endpoint, e.Calls, quotaCell(e.QuotaUnits))
		}
	}
	fmt.Fprintf(tw, "   %s\t%s\t%d\t%d\n", //nolint:errcheck // flushed below
		"TOTAL", "", s.Totals.Calls, s.Totals.QuotaUnits)

	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}

// renderNotes explains the two ways the numbers above can mislead.
func (s Snapshot) renderNotes(w io.Writer) error {
	if s.CountedQuotaCalls > 0 {
		if _, err := fmt.Fprintln(w, " note: endpoint/entity QUOTA values count request attempts as an upper bound, not billed units."); err != nil {
			return err
		}
	}

	if s.QuotaHeaderSeen {
		if _, err := fmt.Fprintln(w, " note: quota headers describe organization-wide state after each request.\n"+
			"       The observed decrease excludes usage before the first header (including\n"+
			"       the first request) and may include other clients' usage."); err != nil {
			return err
		}
	}
	if s.ObservedConsumed != nil && s.CountedQuotaCalls > *s.ObservedConsumed {
		if _, err := fmt.Fprintf(w,
			" note: counted (%d) exceeds observed (%d). Calls are an upper bound, not billed units.\n"+
				"       Flare bills searches/result batches; repeats within 10 minutes can be free,\n"+
				"       and retry billing is undocumented. The observed interval is incomplete.\n",
			s.CountedQuotaCalls, *s.ObservedConsumed); err != nil {
			return err
		}
	}

	undocumented := make([]string, 0)
	for _, e := range s.ByEndpoint {
		if e.QuotaUnits == QuotaUnitsUnknown {
			undocumented = append(undocumented, e.Endpoint)
		}
	}
	if len(undocumented) > 0 {
		if _, err := fmt.Fprintf(w,
			" note: quota billing is undocumented for %s;\n"+
				"       shown as %q and excluded from quota totals.\n",
			strings.Join(undocumented, ", "), quotaUnknownCell); err != nil {
			return err
		}
	}
	return nil
}

// quotaCell renders a quota-unit count, distinguishing "documented as free"
// from "billing unknown".
func quotaCell(units int) string {
	switch {
	case units == QuotaUnitsUnknown:
		return quotaUnknownCell
	case units == 0:
		return quotaFreeCell
	default:
		return strconv.Itoa(units)
	}
}

// humanInt formats an int with thousands separators. Hand-rolled to avoid
// pulling golang.org/x/text in as a direct dependency for one call site.
func humanInt(n int) string {
	s := strconv.Itoa(n)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	if len(s) <= 3 {
		return sign + s
	}

	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
	}
	for i := lead; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return sign + b.String()
}
