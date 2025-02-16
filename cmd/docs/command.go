package docs

import (
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func GenerateDocs(cmd *cobra.Command) error {
	if err := doc.GenMarkdownTree(cmd.Root(), "./docs"); err != nil {
		gologger.Fatal().Msgf("Could not generate markdown docs %s\n", err)
	}
	return nil
}

// Command represents the docs command
var Command = &cobra.Command{
	Use:                   "docs",
	Short:                 "Generate markdown documentation",
	SilenceUsage:          true,
	DisableFlagsInUseLine: true,
	Hidden:                true,
	Args:                  cobra.NoArgs,
	ValidArgsFunction:     cobra.NoFileCompletions,
	Run: func(cmd *cobra.Command, args []string) {
		if err := GenerateDocs(cmd); err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
	},
}
