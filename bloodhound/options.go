package bloodhound

import (
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/cobra"
)

// Options ...
type Options struct {
	BloodhoundUsersJSONFile       string
	FlareCredsByDomainJSONFile    string
	OutputDir                     string
	Neo4jHost                     string
	Neo4jPort                     string
	Neo4jUser                     string
	Neo4jPassword                 string
	BloodhoundUser                string
	BloodhoundPassword            string
	BloodhoundServerURL           string
	UpdateBloodhound              bool
	Verbose                       bool
}

// ConfigureCommand ...
func ConfigureCommand(cmd *cobra.Command) error {
	cmd.PersistentFlags().StringP("bloodhound-users-json-file", "b", "", "Bloodhound JSON file")
	cmd.PersistentFlags().StringP("flare-creds-by-domain-json-file", "f", "", "Flare credentials by domain JSON file")
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
	opts.BloodhoundUser = bloodhoundUser.(string)

	bloodhoundPassword, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "bloodhound-password",
		IsFilePath: false,
		Opts:       opts.BloodhoundPassword,
	})
	if err != nil {
		return err
	}
	opts.BloodhoundPassword = bloodhoundPassword.(string)

	bloodhoundServer, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "bloodhound-server-url",
		IsFilePath: false,
		Opts:       opts.BloodhoundServerURL,
	})
	if err != nil {
		return err
	}
	opts.BloodhoundServerURL = bloodhoundServer.(string)

	bloodHoundUsersJSONFile, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "bloodhound-users-json-file",
		IsFilePath: true,
		Opts:       opts.BloodhoundUsersJSONFile,
	})
	if err != nil {
		return err
	}
	opts.BloodhoundUsersJSONFile = bloodHoundUsersJSONFile.(string)

	flareCredsByDomainJSONFile, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "flare-creds-by-domain-json-file",
		IsFilePath: true,
		Opts:       opts.FlareCredsByDomainJSONFile,
	})
	if err != nil {
		return err
	}
	opts.FlareCredsByDomainJSONFile = flareCredsByDomainJSONFile.(string)

	outputDir, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "output-dir",
		IsFilePath: true,
		Opts:       opts.OutputDir,
	})
	if err != nil {
		return err
	}
	opts.OutputDir = outputDir.(string)

	neo4jHost, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "neo4j-host",
		IsFilePath: false,
		Opts:       opts.Neo4jHost,
	})
	if err != nil {
		return err
	}
	opts.Neo4jHost = neo4jHost.(string)

	neo4jPort, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "neo4j-port",
		IsFilePath: false,
		Opts:       opts.Neo4jPort,
	})
	if err != nil {
		return err
	}
	opts.Neo4jPort = neo4jPort.(string)

	neo4jUser, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "neo4j-user",
		IsFilePath: false,
		Opts:       opts.Neo4jUser,
	})
	if err != nil {
		return err
	}
	opts.Neo4jUser = neo4jUser.(string)

	neo4jPassword, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "neo4j-password",
		IsFilePath: false,
		Opts:       opts.Neo4jPassword,
	})
	if err != nil {
		return err
	}
	opts.Neo4jPassword = neo4jPassword.(string)

	return nil
}
