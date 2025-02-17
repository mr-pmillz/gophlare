package phlare

import (
	"fmt"
	"github.com/mr-pmillz/gophlare/config"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/cobra"
	"reflect"
)

// Options ...
type Options struct {
	APIKeys                         *config.GoPhlareConfig
	Company                         string
	Output                          string
	UserAgent                       string
	Query                           string
	Version                         string
	Domain                          interface{}
	FilesToDownload                 interface{}
	OutOfScope                      interface{}
	Emails                          interface{}
	UserIDFormat                    interface{}
	Timeout                         int
	Years                           int
	MaxZipFilesToDownload           int
	Verbose                         bool
	SearchStealerLogsByDomain       bool
	KeepZipFiles                    bool
	SearchCredentialsByDomain       bool
	SearchEmailsInBulk              bool
	DownloadSpecificStealerLogFiles bool // not yet implemented
}

func ConfigureCommand(cmd *cobra.Command) error {
	// strings
	cmd.PersistentFlags().StringP("company", "c", "", "company name that your testing")
	cmd.PersistentFlags().StringP("query", "q", "", "query to use for searching stealer logs.")
	cmd.PersistentFlags().StringP("output", "o", "", "report output dir")
	cmd.PersistentFlags().StringP("user-agent", "", fmt.Sprintf("gophlare/%s", cmd.Root().Version), "custom user-agent to use for requests")
	// strings of interface type that can be a file, a slice, or a singular string
	cmd.PersistentFlags().StringP("domain", "d", "", "domain string or file containing domains ex. domains.txt")
	cmd.PersistentFlags().StringP("out-of-scope", "", "", "out of scope domains, IPs, or CIDRs")
	cmd.PersistentFlags().StringP("files-to-download", "f", "", "comma separated list of files to match on and download if they exist from the query")
	cmd.PersistentFlags().StringP("emails", "e", "", "emails to check in bulk. Can be a comma separated slice or a file containing emails. ex. emails.txt")
	cmd.PersistentFlags().StringP("user-id-format", "u", "", "if you know the user ID format ex. a12345 , include this to enhance matching in-scope results. can be a string, a file, or comma-separated list of strings")
	// integers
	cmd.PersistentFlags().IntP("years", "y", 2, "number of years in the past to search for stealer logs")
	cmd.PersistentFlags().IntP("timeout", "t", 600, "timeout duration for API requests in seconds")
	cmd.PersistentFlags().IntP("max-zip-download-limit", "m", 50, "maximum number of zip files to download from the stealer logs. Set to 0 to download all zip files.")
	// booleans
	cmd.PersistentFlags().BoolP("search-stealer-logs-by-domain", "", false, "search the stealer logs by domain, download and parse all the matching zip files for passwords and live cookies")
	cmd.PersistentFlags().BoolP("keep-zip-files", "", false, "keep all the matching downloaded zip files from the stealer logs")
	cmd.PersistentFlags().BoolP("search-credentials-by-domain", "", false, "search for credentials by domain")
	cmd.PersistentFlags().BoolP("search-emails-in-bulk", "", false, "search list of emails for credentials.")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")

	cmd.MarkFlagsRequiredTogether("search-emails-in-bulk", "emails")
	return nil
}

// LoadFromCommand ...
//
//nolint:gocognit
func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	apiKeys, err := config.LoadAPIKeys()
	if err != nil {
		utils.LogFatalf("could not load api keys: Error %+v\n", err)
	}
	opts.APIKeys = apiKeys

	opts.Version = cmd.Root().Version

	// Booleans
	cmdVerbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return err
	}
	opts.Verbose = cmdVerbose

	cmdKeepZipFiles, err := cmd.Flags().GetBool("keep-zip-files")
	if err != nil {
		return err
	}
	opts.KeepZipFiles = cmdKeepZipFiles

	cmdSearchCredentialsByDomain, err := cmd.Flags().GetBool("search-credentials-by-domain")
	if err != nil {
		return err
	}
	opts.SearchCredentialsByDomain = cmdSearchCredentialsByDomain

	cmdSearchStealerLogsByDomain, err := cmd.Flags().GetBool("search-stealer-logs-by-domain")
	if err != nil {
		return err
	}
	opts.SearchStealerLogsByDomain = cmdSearchStealerLogsByDomain

	cmdSearchEmailsInBulk, err := cmd.Flags().GetBool("search-emails-in-bulk")
	if err != nil {
		return err
	}
	opts.SearchEmailsInBulk = cmdSearchEmailsInBulk

	// string slices of interface type
	cmdFilesToDownload, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:                 "files-to-download",
		IsFilePath:           true,
		Opts:                 opts.FilesToDownload,
		CommaInStringToSlice: true,
	})
	if err != nil {
		return err
	}
	rt := reflect.TypeOf(cmdFilesToDownload)
	switch rt.Kind() {
	case reflect.Slice:
		opts.FilesToDownload = cmdFilesToDownload.([]string)
	case reflect.String:
		opts.FilesToDownload = cmdFilesToDownload.(string)
	default:
		// Do Nothing
	}

	emails, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:                 "emails",
		IsFilePath:           true,
		Opts:                 opts.Emails,
		CommaInStringToSlice: true,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(emails)
	switch rt.Kind() {
	case reflect.Slice:
		opts.Emails = emails.([]string)
	case reflect.String:
		opts.Emails = emails.(string)
	default:
		// Do Nothing
	}

	userIDFormat, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:                 "user-id-format",
		IsFilePath:           true,
		Opts:                 opts.UserIDFormat,
		CommaInStringToSlice: true,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(userIDFormat)
	switch rt.Kind() {
	case reflect.Slice:
		opts.UserIDFormat = userIDFormat.([]string)
	case reflect.String:
		opts.UserIDFormat = userIDFormat.(string)
	default:
		// Do Nothing
	}

	outOfScope, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:                 "out-of-scope",
		IsFilePath:           true,
		Opts:                 opts.OutOfScope,
		CommaInStringToSlice: true,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(outOfScope)
	switch rt.Kind() {
	case reflect.Slice:
		opts.OutOfScope = outOfScope.([]string)
	case reflect.String:
		opts.OutOfScope = outOfScope.(string)
	default:
		// Do Nothing
	}

	domain, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:                 "domain",
		IsFilePath:           true,
		Opts:                 opts.Domain,
		CommaInStringToSlice: true,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(domain)
	switch rt.Kind() {
	case reflect.Slice:
		opts.Domain = domain.([]string)
	case reflect.String:
		opts.Domain = domain.(string)
	default:
		// Do Nothing
	}

	// regular strings
	company, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:                 "company",
		IsFilePath:           false,
		Opts:                 opts.Company,
		CommaInStringToSlice: false,
	})
	if err != nil {
		return err
	}
	opts.Company = company.(string)

	userAgent, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "user-agent",
		IsFilePath: false,
		Opts:       opts.UserAgent,
	})
	if err != nil {
		return err
	}
	opts.UserAgent = userAgent.(string)

	output, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "output",
		IsFilePath: true,
		Opts:       opts.Output,
	})
	if err != nil {
		return err
	}
	opts.Output = output.(string)

	// integers
	cmdTimeout, err := cmd.Flags().GetInt("timeout")
	if err != nil {
		return err
	}
	opts.Timeout = cmdTimeout

	cmdYears, err := cmd.Flags().GetInt("years")
	if err != nil {
		return err
	}
	opts.Years = cmdYears

	cmdMaxZipsDownloadLimit, err := cmd.Flags().GetInt("max-zip-download-limit")
	if err != nil {
		return err
	}
	opts.MaxZipFilesToDownload = cmdMaxZipsDownloadLimit

	return nil
}
