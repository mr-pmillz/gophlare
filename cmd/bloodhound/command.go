package bloodhound

import (
	"github.com/mr-pmillz/gophlare/bloodhound"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/cobra"
	"os"
)

// Options ...
type Options struct {
	bloodhoundOptions bloodhound.Options
}

func configureCommand(cmd *cobra.Command) {
	_ = bloodhound.ConfigureCommand(cmd)
}

// LoadFromCommand loads configuration options from the provided cobra.Command into the current Options instance.
func (opts *Options) LoadFromCommand(cmd *cobra.Command) error {
	return opts.bloodhoundOptions.LoadFromCommand(cmd)
}

// Command defines a cobra command for running search enumeration processes with support for various configurations and flags.
var Command = &cobra.Command{
	Use:   "bloodhound",
	Args:  cobra.MinimumNArgs(0),
	Short: "correlate breach data with bloodhound data",
	Long: `correlate breach data with bloodhound data

Example Commands:
	gophlare bloodhound --config config.yaml
`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if configFileSet, err := cmd.Flags().GetBool("configfileset"); !configFileSet && err == nil {
			_ = cmd.MarkPersistentFlagRequired("output-dir")
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
		case opts.bloodhoundOptions.OutputDir == "":
			utils.LogFatalf("OUTPUT_DIR cannot be empty!")
		}

		if err = os.MkdirAll(opts.bloodhoundOptions.OutputDir, 0750); err != nil {
			utils.LogFatalf("Error creating directory:  %s\n", err)
		}

		if err = UpdateADUsersMetadata(&opts.bloodhoundOptions); err != nil {
			utils.LogFatalf("Could not update AD users metadata: %s\n", err)
		}
	},
}

func init() {
	configureCommand(Command)
}
