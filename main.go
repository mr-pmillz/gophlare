package main

import (
	"fmt"
	"github.com/mr-pmillz/gophlare/cmd"
	"github.com/projectdiscovery/gologger"
	"os"
)

func main() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		gologger.Warning().Msgf("Could not get user homedir. Error: %+v\n", err)
	}
	if err = os.MkdirAll(fmt.Sprintf("%s/.config/gophlare", homeDir), 0750); err != nil {
		gologger.Warning().Msgf("Could not Create directory: ~/.config/gophlare\n Error: %+v\n", err)
	}

	if err = cmd.RootCmd.Execute(); err != nil {
		gologger.Fatal().Msgf("Could not run root command %+v\n", err)
	}
}
