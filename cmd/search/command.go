package search

import (
	"os"
	"reflect"

	"github.com/mr-pmillz/gophlare/metrics"
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/cobra"
)

// reportMetrics emits the Flare API usage report. Safe to call more than once —
// ReportOnce is sync.Once-guarded — and a no-op unless --metrics is set.
func reportMetrics(opts *phlare.Options) {
	if err := metrics.Default().ReportOnce(metrics.ReportOptions{
		Enabled:      opts.Metrics,
		MonthlyQuota: opts.MonthlyQuota,
		OutputDir:    opts.Output,
		Version:      opts.Version,
		Colorize:     true,
	}); err != nil {
		utils.LogWarningf("could not write Flare API metrics report: %s\n", err.Error())
	}
}

// fatalf reports API usage before exiting. Quota is spent even when a run
// fails, and utils.LogFatalf calls os.Exit, which skips deferred work — so the
// report has to happen here rather than in a defer.
func fatalf(opts *phlare.Options, format string, args ...any) {
	reportMetrics(opts)
	utils.LogFatalf(format, args...)
}

type Options struct {
	gophlareOptions phlare.Options
}

func configureCommand(cmd *cobra.Command) {
	_ = phlare.ConfigureCommand(cmd)
}

// LoadFromCommand loads configuration options from the provided cobra.Command into the current Options instance.
func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	return opts.gophlareOptions.LoadFromCommand(cmd)
}

// Command defines a cobra command for running search enumeration processes with support for various configurations and flags.
var Command = &cobra.Command{
	Use:   "search",
	Args:  cobra.MinimumNArgs(0),
	Short: "search the flare api for leaks",
	Long: `search the flare api for credentials, emails, and stealer logs

Example Commands:
	gophlare search --config config.yaml --search-credentials-by-domain
	gophlare search --config config.yaml --search-stealer-logs-by-host-domain
	gophlare search --config config.yaml --search-stealer-logs-by-wildcard-host --keep-zip-files --max-zip-download-limit 0
	gophlare search --config config.yaml --search-stealer-logs-by-domain --keep-zip-files --max-zip-download-limit 0
	gophlare search --config config.yaml --search-stealer-logs-by-domain --query 'metadata.source:stealer_logs* AND features.FOO:BAR'
	gophlare search --config config.yaml --search-emails-in-bulk -e emails.txt -o output-directory
`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if configFileSet, err := cmd.Flags().GetBool("configfileset"); !configFileSet && err == nil {
			// _ = cmd.MarkPersistentFlagRequired("domain")
			_ = cmd.MarkPersistentFlagRequired("output")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		opts := Options{}
		if err = opts.LoadFromCommand(cmd); err != nil {
			utils.LogFatalf("Could not LoadFromCommand: %s\n", err)
		}

		// ensure required flags represented via config.yaml parsed by viper are not empty!
		switch {
		case opts.gophlareOptions.Output == "":
			fatalf(&opts.gophlareOptions, "OUTPUT cannot be empty!")
		case reflect.TypeOf(opts.gophlareOptions.Domains).Kind() == reflect.String:
			if opts.gophlareOptions.Domains.(string) == "" && opts.gophlareOptions.Query == "" {
				fatalf(&opts.gophlareOptions, "DOMAINS and QUERY cannot both be empty!")
			}
		}

		if err = os.MkdirAll(opts.gophlareOptions.Output, 0750); err != nil {
			fatalf(&opts.gophlareOptions, "Error creating directory:  %s\n", err)
		}

		scope, err := phlare.NewScope(&opts.gophlareOptions)
		if err != nil {
			fatalf(&opts.gophlareOptions, "Could not create NewScope %s\n", err)
		}

		if opts.gophlareOptions.APIKeys.APIKeys.FlareAPI == "" || opts.gophlareOptions.APIKeys.APIKeys.FlareTenantID == 0 {
			fatalf(&opts.gophlareOptions, "Flare API Key and Flare Tenant ID are required to use this tool!")
		}

		if opts.gophlareOptions.SearchStealerLogsByDomain || opts.gophlareOptions.SearchStealerLogsByHostDomain || opts.gophlareOptions.SearchStealerLogsByWildcardHost {
			if err := DownloadAllStealerLogPasswordFiles(&opts.gophlareOptions, scope); err != nil {
				fatalf(&opts.gophlareOptions, "Could not download all stealer log password files %s\n", err)
			}
		}

		if opts.gophlareOptions.SearchCredentialsByDomain {
			_, err := FlareLeaksDatabaseSearchByDomain(&opts.gophlareOptions, scope.Domains)
			if err != nil {
				fatalf(&opts.gophlareOptions, "Could not search flare leaks database by domain: %+v\n%s\n", scope.Domains, err)
			}
		}

		if opts.gophlareOptions.Emails != nil && opts.gophlareOptions.SearchEmailsInBulk {
			if err := SearchEmailsInBulk(&opts.gophlareOptions, scope.Emails); err != nil {
				fatalf(&opts.gophlareOptions, "Could not search emails in bulk: %+v\n%s\n", scope.Emails, err)
			}
		}
	},
}

func init() {
	configureCommand(Command)
}
