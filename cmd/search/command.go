package search

import (
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/cobra"
	"os"
	"reflect"
)

type Options struct {
	gophlareOptions phlare.Options
}

func configureCommand(cmd *cobra.Command) {
	_ = phlare.ConfigureCommand(cmd)
}

// LoadFromCommand ...
func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	return opts.gophlareOptions.LoadFromCommand(cmd)
}

// Command ...
var Command = &cobra.Command{
	Use:   "search",
	Args:  cobra.MinimumNArgs(0),
	Short: "Run search enumeration",
	Long: `Run search enumeration

Example Commands:
	gophlare search --config config.yaml
`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if configFileSet, err := cmd.Flags().GetBool("configfileset"); !configFileSet && err == nil {
			_ = cmd.MarkPersistentFlagRequired("company")
			_ = cmd.MarkPersistentFlagRequired("domain")
			_ = cmd.MarkPersistentFlagRequired("output")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		opts := Options{}
		if err = opts.LoadFromCommand(cmd); err != nil {
			utils.LogFatalf("Could not LoadFromCommand %s\n", err)
		}

		// ensure required flags represented via config.yaml parsed by viper are not empty!
		switch {
		case opts.gophlareOptions.Output == "":
			utils.LogFatalf("OUTPUT config.yaml value cannot be empty!")
		case reflect.TypeOf(opts.gophlareOptions.Domain).Kind() == reflect.String:
			if opts.gophlareOptions.Domain.(string) == "" {
				utils.LogFatalf("DOMAIN value cannot be empty!")
			}
		}

		if err = os.MkdirAll(opts.gophlareOptions.Output, 0750); err != nil {
			utils.LogFatalf("Error creating directory:  %s\n", err)
		}

		scope, err := phlare.NewScope(&opts.gophlareOptions)
		if err != nil {
			utils.LogFatalf("Could not create NewScope %s\n", err)
		}

		if opts.gophlareOptions.APIKeys.APIKeys.FlareAPI == "" || opts.gophlareOptions.APIKeys.APIKeys.FlareTenantID == 0 {
			utils.LogFatalf("Flare API Key and Flare Tenant ID are required to use this tool!")
		}

		if opts.gophlareOptions.SearchStealerLogsByDomain {
			if err := phlare.DownloadAllStealerLogPasswordFiles(&opts.gophlareOptions, scope.Domains); err != nil {
				utils.LogFatalf("Could not download all stealer log password files %s\n", err)
			}
		}

		if opts.gophlareOptions.SearchCredentialsByDomain {
			_, err := phlare.SearchFlareLeaksDatabase(&opts.gophlareOptions, scope.Domains)
			if err != nil {
				utils.LogFatalf("Could not search flare leaks database by domain: %+v\n%s\n", scope.Domains, err)
			}
		}

		if opts.gophlareOptions.Emails != nil && opts.gophlareOptions.SearchEmailsInBulk {
			if err := phlare.SearchEmailsInBulk(&opts.gophlareOptions, scope.Emails); err != nil {
				utils.LogFatalf("Could not search emails in bulk: %+v\n%s\n", scope.Emails, err)
			}
		}
	},
}

func init() {
	configureCommand(Command)
}
