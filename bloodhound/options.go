package bloodhound

import (
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/cobra"
)

// Options ...
type Options struct {
	BloodhoundUsersJSONFile    string
	FlareCredsByDomainJSONFile string
	StealerLogsLeaksCSVFile    string
	HostLeaksJSONFile          string // custom leak data file
	OutputDir                  string
	Neo4jHost                  string
	Neo4jPort                  string
	Neo4jUser                  string
	Neo4jPassword              string
	BloodhoundUser             string
	BloodhoundPassword         string
	BloodhoundServerURL        string
	UpdateBloodhound           bool
	Verbose                    bool
}

// ConfigureCommand ...
func ConfigureCommand(cmd *cobra.Command) error {
	cmd.PersistentFlags().StringP("bloodhound-users-json-file", "b", "", "Bloodhound JSON file")
	cmd.PersistentFlags().StringP("flare-creds-by-domain-json-file", "f", "", "Flare credentials by domain JSON file")
	cmd.PersistentFlags().StringP("stealer-logs-leaks-csv-file", "", "", "Flare stealer logs leaks CSV file, optional")
	cmd.PersistentFlags().StringP("host-leaks-json-file", "", "", "Host leaks JSON file, optional, custom from hoard client, you probs shouldn't use this option unless you know what you're doing") // custom leak data file
	cmd.PersistentFlags().StringP("output-dir", "o", "", "Output directory")
	cmd.PersistentFlags().StringP("neo4j-host", "", "", "Neo4j host")
	cmd.PersistentFlags().StringP("neo4j-port", "", "", "Neo4j port")
	cmd.PersistentFlags().StringP("neo4j-user", "", "", "Neo4j user")
	cmd.PersistentFlags().StringP("neo4j-password", "", "", "Neo4j password")
	cmd.PersistentFlags().StringP("bloodhound-user", "", "", "Bloodhound user")
	cmd.PersistentFlags().StringP("bloodhound-password", "", "", "Bloodhound password")
	cmd.PersistentFlags().StringP("bloodhound-server-url", "", "", "Bloodhound server base URL, ex: http://127.0.0.1:8001")
	cmd.PersistentFlags().BoolP("update-bloodhound", "", false, "update bloodhound neo4j database with breach data")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")

	cmd.PersistentFlags().BoolP("configfileset", "c", false, "Config file set")
	return nil
}

// LoadFromCommand loads command-line arguments and flags into the Options struct. It validates and processes the provided inputs.
func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	// Booleans
	cmdVerbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return err
	}
	opts.Verbose = cmdVerbose

	cmdUpdateBloodhound, err := cmd.Flags().GetBool("update-bloodhound")
	if err != nil {
		return err
	}
	opts.UpdateBloodhound = cmdUpdateBloodhound

	// string options that are available via config.yaml parsed by viper
	bloodhoundUser, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "bloodhound-user",
		IsFilePath: false,
		Opts:       opts.BloodhoundUser,
	})
	if err != nil {
		return err
	}
	if bloodhoundUserStr, ok := bloodhoundUser.(string); ok {
		opts.BloodhoundUser = bloodhoundUserStr
	}

	bloodhoundPassword, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "bloodhound-password",
		IsFilePath: false,
		Opts:       opts.BloodhoundPassword,
	})
	if err != nil {
		return err
	}
	if bloodhoundPasswordStr, ok := bloodhoundPassword.(string); ok {
		opts.BloodhoundPassword = bloodhoundPasswordStr
	}

	bloodhoundServer, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "bloodhound-server-url",
		IsFilePath: false,
		Opts:       opts.BloodhoundServerURL,
	})
	if err != nil {
		return err
	}
	if bloodhoundServerStr, ok := bloodhoundServer.(string); ok {
		opts.BloodhoundServerURL = bloodhoundServerStr
	}

	bloodHoundUsersJSONFile, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "bloodhound-users-json-file",
		IsFilePath: true,
		Opts:       opts.BloodhoundUsersJSONFile,
	})
	if err != nil {
		return err
	}
	if bloodHoundUsersJSONFileStr, ok := bloodHoundUsersJSONFile.(string); ok {
		opts.BloodhoundUsersJSONFile = bloodHoundUsersJSONFileStr
	}

	flareCredsByDomainJSONFile, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "flare-creds-by-domain-json-file",
		IsFilePath: true,
		Opts:       opts.FlareCredsByDomainJSONFile,
	})
	if err != nil {
		return err
	}
	if flareCredsByDomainJSONFileStr, ok := flareCredsByDomainJSONFile.(string); ok {
		opts.FlareCredsByDomainJSONFile = flareCredsByDomainJSONFileStr
	}

	stealerLogsLeaksCSVFile, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "stealer-logs-leaks-csv-file",
		IsFilePath: true,
		Opts:       opts.StealerLogsLeaksCSVFile,
	})
	if err != nil {
		return err
	}
	if stealerLogsLeaksCSVFileStr, ok := stealerLogsLeaksCSVFile.(string); ok {
		opts.StealerLogsLeaksCSVFile = stealerLogsLeaksCSVFileStr
	}

	hostLeaksJSONFile, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "host-leaks-json-file",
		IsFilePath: true,
		Opts:       opts.HostLeaksJSONFile,
	})
	if err != nil {
		return err
	}
	if hostLeaksJSONFileStr, ok := hostLeaksJSONFile.(string); ok {
		opts.HostLeaksJSONFile = hostLeaksJSONFileStr
	}

	outputDir, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "output-dir",
		IsFilePath: true,
		Opts:       opts.OutputDir,
	})
	if err != nil {
		return err
	}
	if outputDirStr, ok := outputDir.(string); ok {
		opts.OutputDir = outputDirStr
	}

	neo4jHost, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "neo4j-host",
		IsFilePath: false,
		Opts:       opts.Neo4jHost,
	})
	if err != nil {
		return err
	}
	if neo4jHostStr, ok := neo4jHost.(string); ok {
		opts.Neo4jHost = neo4jHostStr
	}

	neo4jPort, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "neo4j-port",
		IsFilePath: false,
		Opts:       opts.Neo4jPort,
	})
	if err != nil {
		return err
	}
	if neo4jPortStr, ok := neo4jPort.(string); ok {
		opts.Neo4jPort = neo4jPortStr
	}

	neo4jUser, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "neo4j-user",
		IsFilePath: false,
		Opts:       opts.Neo4jUser,
	})
	if err != nil {
		return err
	}
	if neo4jUserStr, ok := neo4jUser.(string); ok {
		opts.Neo4jUser = neo4jUserStr
	}

	neo4jPassword, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "neo4j-password",
		IsFilePath: false,
		Opts:       opts.Neo4jPassword,
	})
	if err != nil {
		return err
	}
	if neo4jPasswordStr, ok := neo4jPassword.(string); ok {
		opts.Neo4jPassword = neo4jPasswordStr
	}

	return nil
}
