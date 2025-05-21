package bloodhound

import (
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/cobra"
)

// Options ...
type Options struct {
	BloodhoundUsersJSONFile       string
	FlareCredsByDomainJSONFile    string
	GoldmineCredsByDomainJSONFile string
	LinkedinScrapeJSONFile        string
	OutputDir                     string
	Neo4jHost                     string
	Neo4jPort                     string
	Neo4jUser                     string
	Neo4jPassword                 string
	UpdateBloodhound              bool
	Verbose                       bool
}

// ConfigureCommand ...
func ConfigureCommand(cmd *cobra.Command) error {
	cmd.PersistentFlags().StringP("bloodhound-users-json-file", "b", "", "Bloodhound JSON file")
	cmd.PersistentFlags().StringP("flare-creds-by-domain-json-file", "f", "", "Flare credentials by domain JSON file")
	cmd.PersistentFlags().StringP("goldmine-creds-by-domain-json-file", "g", "", "Goldmine credentials by domain JSON file")
	cmd.PersistentFlags().StringP("linkedin-scrape-json-file", "l", "", "Goldmine LinkedIn Scrape JSON file")
	cmd.PersistentFlags().StringP("output-dir", "o", "", "Output directory")
	cmd.PersistentFlags().StringP("neo4j-host", "", "127.0.0.1", "Neo4j host")
	cmd.PersistentFlags().StringP("neo4j-port", "", "7687", "Neo4j port")
	cmd.PersistentFlags().StringP("neo4j-user", "", "neo4j", "Neo4j user")
	cmd.PersistentFlags().StringP("neo4j-password", "", "neo5j", "Neo4j password")
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

	GoldmineCredsByDomainJSONFile, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "goldmine-creds-by-domain-json-file",
		IsFilePath: true,
		Opts:       opts.GoldmineCredsByDomainJSONFile,
	})
	if err != nil {
		return err
	}
	opts.GoldmineCredsByDomainJSONFile = GoldmineCredsByDomainJSONFile.(string)

	LinkedinScrapeJSONFile, err := utils.ConfigureFlagOpts(cmd, &utils.LoadFromCommandOpts{
		Flag:       "linkedin-scrape-json-file",
		IsFilePath: true,
		Opts:       opts.LinkedinScrapeJSONFile,
	})
	if err != nil {
		return err
	}
	opts.LinkedinScrapeJSONFile = LinkedinScrapeJSONFile.(string)

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
