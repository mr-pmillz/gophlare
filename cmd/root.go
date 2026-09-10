package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/mr-pmillz/gophlare/cmd/bloodhound"
	"github.com/mr-pmillz/gophlare/cmd/docs"
	"github.com/mr-pmillz/gophlare/cmd/search"
	"github.com/mr-pmillz/gophlare/metrics"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	cfgFile       string
	version       = "v1.5.0"
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

// reportFlareAPIUsage emits the Flare API usage report after a subcommand
// finishes. Registered on the root so any future Flare-touching subcommand gets
// it for free; it no-ops for commands that define no --metrics flag, such as
// `gophlare bloodhound`, which makes no Flare API calls at all.
//
// This covers the success path. The failure path is handled by the fatalf
// helper in cmd/search, because utils.LogFatalf calls os.Exit and would skip
// this hook — and quota is spent even when a run fails. ReportOnce is
// sync.Once-guarded, so both firing is harmless.
func reportFlareAPIUsage(cmd *cobra.Command, _ []string) {
	enabled, err := cmd.Flags().GetBool("metrics")
	if err != nil || !enabled {
		return
	}

	monthlyQuota, err := cmd.Flags().GetInt("monthly-quota")
	if err != nil {
		monthlyQuota = metrics.DefaultMonthlyQuota
	}
	outputDir, _ := cmd.Flags().GetString("output")

	if err := metrics.Default().ReportOnce(metrics.ReportOptions{
		Enabled:      true,
		MonthlyQuota: monthlyQuota,
		OutputDir:    outputDir,
		Version:      cmd.Root().Version,
		Colorize:     true,
	}); err != nil {
		utils.LogWarningf("could not write Flare API metrics report: %s\n", err.Error())
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentPostRun = reportFlareAPIUsage
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
