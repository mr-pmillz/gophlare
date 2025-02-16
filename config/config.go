package config

import (
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/viper"
)

// LoadAPIKeys ...
func LoadAPIKeys() (*GoPhlareConfig, error) {
	var config GoPhlareConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, utils.LogError(err)
	}

	return &config, nil
}

// GoPhlareConfig ...
type GoPhlareConfig struct {
	APIKeys struct {
		FlareAPI      string `mapstructure:"FLARE_API"`
		FlareTenantID int    `mapstructure:"FLARE_TENANT_ID"`
	} `mapstructure:"API_KEYS"`
}
