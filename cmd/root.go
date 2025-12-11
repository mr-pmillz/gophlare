package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/mr-pmillz/gophlare/cmd/bloodhound"
	"github.com/mr-pmillz/gophlare/cmd/docs"
	"github.com/mr-pmillz/gophlare/cmd/search"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	cfgFile       string
	version       = "v1.3.6"
	configFileSet bool
)

const (
	defaultConfigFileName = "config"
	envPrefix             = "GOFLARE"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:     "gophlare",
	Version: version,
	Short:   "client for flare.io api",
	Long:    `client for flare.io api`,
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file default location for viper to look is ~/.config/gophlare/config.yaml")
	RootCmd.PersistentFlags().BoolVarP(&configFileSet, "configfileset", "", false, "Used internally by gophlare to check if required args are set with and without configuration file, Do not use this flag...")
	RootCmd.AddCommand(search.Command)
	RootCmd.AddCommand(bloodhound.Command)
	RootCmd.AddCommand(docs.Command)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		absConfigFilePath, err := utils.ResolveAbsPath(cfgFile)
		if err != nil {
			_ = fmt.Errorf("couldn't resolve path of config file: %w", err)
			return
		}
		viper.SetConfigFile(absConfigFilePath)
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			gologger.Warning().Msgf("Could not get user homedir. Error: %+v\n", err)
		}
		// Search config in $HOME/.config/gophlare/config.yaml directory with name "config.yaml"
		viper.AddConfigPath(fmt.Sprintf("%s/.config/gophlare", homeDir))
		viper.SetConfigType("yaml")
		viper.SetConfigName(defaultConfigFileName)
	}

	// If a config file is found, read it.
	if err := viper.ReadInConfig(); err == nil {
		configFileSet = true
		utils.InfoLabelf("ConfigFile", "Using config file: %s", viper.ConfigFileUsed())
	}
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv() // read in environment variables that match
	bindFlags(RootCmd)
}

// bindFlags Bind each cobra flag to its associated viper configuration (config file and environment variable)
func bindFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR
		envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		err := viper.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix))
		if err != nil {
			return
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(f.Name) {
			val := viper.Get(f.Name)
			err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				return
			}
		}
	})
}
