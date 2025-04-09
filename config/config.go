package config

import (
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/spf13/viper"
)

// NewGoPhlareConfig ...
//
//nolint:unused
func NewGoPhlareConfig(flareAPI string, flareTenantID int) *GoPhlareConfig {
	config := &GoPhlareConfig{}
	config.APIKeys.FlareAPI = flareAPI
	config.APIKeys.FlareTenantID = flareTenantID
	return config
}

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
