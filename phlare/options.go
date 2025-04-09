package phlare

import (
	"github.com/mr-pmillz/gophlare/config"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/cobra"
	"reflect"
	"time"
)

// Options holds configuration options for various command-line arguments and flags.
// The struct includes settings for API keys, user information, query parameters, file processing, and operational flags.
type Options struct {
	APIKeys                         *config.GoPhlareConfig
	Company                         string
	Output                          string
	UserAgent                       string
	Query                           string
	Version                         string
	From                            string
	To                              string
	Domain                          interface{}
	FilesToDownload                 interface{}
	OutOfScope                      interface{}
	Emails                          interface{}
	UserIDFormat                    interface{}
	Severity                        interface{}
	EventsFilterTypes               interface{}
	Timeout                         int
	MaxZipFilesToDownload           int
	Verbose                         bool
	SearchStealerLogsByDomain       bool
	KeepZipFiles                    bool
	SearchCredentialsByDomain       bool
	SearchEmailsInBulk              bool
	DownloadSpecificStealerLogFiles bool // not yet implemented
}

// todaysDate gets today's date as a string in RFC3339 format
func todaysDate() string {
	const layout = "2006-01-02"
	return time.Now().UTC().Format(layout)
}

func ConfigureCommand(cmd *cobra.Command) error {
	// strings
	cmd.PersistentFlags().StringP("company", "c", "", "company name that your testing")
	cmd.PersistentFlags().StringP("query", "q", "", "query to use for searching stealer logs.")
	cmd.PersistentFlags().StringP("output", "o", "", "report output dir")
	cmd.PersistentFlags().StringP("user-agent", "", "", "custom user-agent to use for requests")
	cmd.PersistentFlags().StringP("from", "f", "", "from date used for a filter for stealer log searches. ex. 2021-01-01 ")
	cmd.PersistentFlags().StringP("to", "", todaysDate(), "to date used for a filter for stealer log searches. ex. 2025-01-01. Defaults to today.")
	// strings of interface type that can be a file, a slice, or a singular string
	cmd.PersistentFlags().StringP("domain", "d", "", "domain string, can be a file file containing domains ex. domains.txt, or comma-separated list of strings")
	cmd.PersistentFlags().StringP("out-of-scope", "", "", "out of scope domains, IPs, or CIDRs")
	cmd.PersistentFlags().StringP("files-to-download", "", "", "comma separated list of files to match on and download if they exist from the query")
	cmd.PersistentFlags().StringP("emails", "e", "", "emails to check in bulk. Can be a comma separated slice or a file containing emails. ex. emails.txt")
	cmd.PersistentFlags().StringP("user-id-format", "u", "", "if you know the user ID format ex. a12345 , include this to enhance matching in-scope results. can be a string, a file, or comma-separated list of strings")
	cmd.PersistentFlags().StringP("severity", "s", "medium,high,critical", "the stealer log severities to filter on. can be a string, a file, or comma-separated list of strings")
	cmd.PersistentFlags().StringP("events-filter-types", "", "illicit_networks,open_web,leak,domain,listing,forum_content,blog_content,blog_post,profile,chat_message,ransomleak,infected_devices,financial_data,bot,stealer_log,paste,social_media,source_code,source_code_files,stack_exchange,google,service,buckets,bucket,bucket_object", "flare global events filter types. Available values: illicit_networks,open_web,leak,domain,listing,forum_content,blog_content,blog_post,profile,chat_message,ransomleak,infected_devices,financial_data,bot,stealer_log,paste,social_media,source_code,source_code_files,stack_exchange,google,service,buckets,bucket,bucket_object. can be a string, or comma-separated list of strings")
	// integers
	cmd.PersistentFlags().IntP("timeout", "", 600, "timeout duration for API requests in seconds")
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

// LoadFromCommand loads command-line arguments and flags into the Options struct. It validates and processes the provided inputs.
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

	severity, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:                 "severity",
		IsFilePath:           true,
		Opts:                 opts.Severity,
		CommaInStringToSlice: true,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(severity)
	switch rt.Kind() {
	case reflect.Slice:
		opts.Severity = severity.([]string)
	case reflect.String:
		opts.Severity = severity.(string)
	default:
		// Do Nothing
	}

	eventsFilterTypes, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:                 "events-filter-types",
		IsFilePath:           false,
		Opts:                 opts.EventsFilterTypes,
		CommaInStringToSlice: true,
	})
	if err != nil {
		return err
	}
	rt = reflect.TypeOf(eventsFilterTypes)
	switch rt.Kind() {
	case reflect.Slice:
		opts.EventsFilterTypes = eventsFilterTypes.([]string)
	case reflect.String:
		opts.EventsFilterTypes = eventsFilterTypes.(string)
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

	// timestamp strings
	from, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "from",
		IsFilePath: false,
		Opts:       opts.From,
	})
	if err != nil {
		return err
	}
	fromTimeStamp, err := utils.FormatDate(from.(string))
	if err != nil {
		return err
	}
	opts.From = fromTimeStamp

	to, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "to",
		IsFilePath: false,
		Opts:       opts.To,
	})
	if err != nil {
		return err
	}
	toTimeStamp, err := utils.FormatDate(to.(string))
	if err != nil {
		return err
	}
	opts.To = toTimeStamp

	// integers
	cmdTimeout, err := cmd.Flags().GetInt("timeout")
	if err != nil {
		return err
	}
	opts.Timeout = cmdTimeout

	cmdMaxZipsDownloadLimit, err := cmd.Flags().GetInt("max-zip-download-limit")
	if err != nil {
		return err
	}
	opts.MaxZipFilesToDownload = cmdMaxZipsDownloadLimit

	return nil
}
