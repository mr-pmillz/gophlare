package utils

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type LoadFromCommandOpts struct {
	DefaultFlagVal       string
	Flag                 string
	IsFilePath           bool
	CommaInStringToSlice bool
	Prefix               string
	Opts                 interface{}
}

// ConfigureFlagOpts sets the cobra flag option to the LoadFromCommandOpts.Opts key
// it returns the parsed value of the cobra flag from LoadFromCommandOpts.Flag
// Supports string, int, bool, and string slices (comma-separated or YAML list via Viper).
//
//nolint:gocognit
func ConfigureFlagOpts(cmd *cobra.Command, lfcOpts *LoadFromCommandOpts) (interface{}, error) {
	name := fmt.Sprintf("%s%s", lfcOpts.Prefix, lfcOpts.Flag)
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))

	// Type hints from current Opts value
	_, wantInt := lfcOpts.Opts.(int)
	_, wantBool := lfcOpts.Opts.(bool)
	_, wantSlice := lfcOpts.Opts.([]string)

	// Prefer explicit CLI flag value when provided
	if cmd.Flags().Changed(name) {
		if wantInt {
			v, err := cmd.Flags().GetInt(name)
			if err != nil {
				return nil, err
			}
			lfcOpts.Opts = v
			return lfcOpts.Opts, nil
		}
		if wantBool {
			v, err := cmd.Flags().GetBool(name)
			if err != nil {
				return nil, err
			}
			lfcOpts.Opts = v
			return lfcOpts.Opts, nil
		}
		// strings (and potential comma-splitting)
		s, err := cmd.Flags().GetString(name)
		if err != nil {
			return nil, err
		}
		if wantSlice {
			if lfcOpts.CommaInStringToSlice && strings.Contains(s, ",") {
				lfcOpts.Opts = strings.Split(s, ",")
				return lfcOpts.Opts, nil
			}
			lfcOpts.Opts = []string{s}
			return lfcOpts.Opts, nil
		}
		if lfcOpts.IsFilePath {
			if exists, err := Exists(s); err == nil && exists {
				if abs, err := ResolveAbsPath(s); err == nil {
					lfcOpts.Opts = abs
					return lfcOpts.Opts, nil
				} else {
					return nil, err
				}
			}
			// File doesn't exist - use raw value (e.g., domain name)
			// Don't call ResolveAbsPath which would add leading / in containers
			lfcOpts.Opts = s
			return lfcOpts.Opts, nil
		}
		if lfcOpts.CommaInStringToSlice && strings.Contains(s, ",") {
			lfcOpts.Opts = strings.Split(s, ",")
			return lfcOpts.Opts, nil
		}
		lfcOpts.Opts = s
		return lfcOpts.Opts, nil
	}

	// Not provided via CLI: consider ENV indirection then config
	configStr := viper.GetString(upper)
	configSlice := viper.GetStringSlice(upper)
	if envVal, ok := os.LookupEnv(configStr); ok {
		if wantInt {
			if iv, err := strconv.Atoi(envVal); err == nil {
				lfcOpts.Opts = iv
				return lfcOpts.Opts, nil
			}
		}
		if wantBool {
			if bv, err := strconv.ParseBool(envVal); err == nil {
				lfcOpts.Opts = bv
				return lfcOpts.Opts, nil
			}
		}
		if wantSlice {
			if lfcOpts.CommaInStringToSlice && strings.Contains(envVal, ",") {
				lfcOpts.Opts = strings.Split(envVal, ",")
				return lfcOpts.Opts, nil
			}
			lfcOpts.Opts = []string{envVal}
			return lfcOpts.Opts, nil
		}
		// string/filepath
		if lfcOpts.IsFilePath {
			if exists, err := Exists(envVal); err == nil && exists {
				if abs, err := ResolveAbsPath(envVal); err == nil {
					lfcOpts.Opts = abs
					return lfcOpts.Opts, nil
				} else {
					return nil, err
				}
			}
			lfcOpts.Opts = envVal
			return lfcOpts.Opts, nil
		}
		lfcOpts.Opts = envVal
		return lfcOpts.Opts, nil
	}

	// Config values
	if wantInt {
		if viper.IsSet(upper) {
			lfcOpts.Opts = viper.GetInt(upper)
			return lfcOpts.Opts, nil
		}
		if lfcOpts.DefaultFlagVal != "" {
			if iv, err := strconv.Atoi(lfcOpts.DefaultFlagVal); err == nil {
				lfcOpts.Opts = iv
				return lfcOpts.Opts, nil
			}
		}
		return lfcOpts.Opts, nil
	}
	if wantBool {
		if viper.IsSet(upper) {
			lfcOpts.Opts = viper.GetBool(upper)
			return lfcOpts.Opts, nil
		}
		if lfcOpts.DefaultFlagVal != "" {
			if bv, err := strconv.ParseBool(lfcOpts.DefaultFlagVal); err == nil {
				lfcOpts.Opts = bv
				return lfcOpts.Opts, nil
			}
		}
		return lfcOpts.Opts, nil
	}
	if wantSlice {
		if len(configSlice) > 0 {
			lfcOpts.Opts = configSlice
			return lfcOpts.Opts, nil
		}
		if configStr != "" {
			if lfcOpts.CommaInStringToSlice && strings.Contains(configStr, ",") {
				lfcOpts.Opts = strings.Split(configStr, ",")
				return lfcOpts.Opts, nil
			}
			lfcOpts.Opts = []string{configStr}
			return lfcOpts.Opts, nil
		}
		if lfcOpts.DefaultFlagVal != "" {
			if lfcOpts.CommaInStringToSlice && strings.Contains(lfcOpts.DefaultFlagVal, ",") {
				lfcOpts.Opts = strings.Split(lfcOpts.DefaultFlagVal, ",")
				return lfcOpts.Opts, nil
			}
			lfcOpts.Opts = []string{lfcOpts.DefaultFlagVal}
			return lfcOpts.Opts, nil
		}
		return lfcOpts.Opts, nil
	}

	// string fallback
	if configStr != "" {
		if lfcOpts.IsFilePath {
			if exists, err := Exists(configStr); err == nil && exists {
				if abs, err := ResolveAbsPath(configStr); err == nil {
					lfcOpts.Opts = abs
					return lfcOpts.Opts, nil
				} else {
					return nil, err
				}
			}
			lfcOpts.Opts = configStr
			return lfcOpts.Opts, nil
		}
		lfcOpts.Opts = configStr
		return lfcOpts.Opts, nil
	}

	// defaults for strings
	if lfcOpts.DefaultFlagVal != "" {
		if lfcOpts.IsFilePath {
			if abs, err := ResolveAbsPath(lfcOpts.DefaultFlagVal); err == nil {
				if _, statErr := os.Stat(abs); os.IsNotExist(statErr) {
					lfcOpts.Opts = ""
				} else {
					lfcOpts.Opts = abs
				}
			} else {
				return nil, err
			}
		} else {
			lfcOpts.Opts = lfcOpts.DefaultFlagVal
		}
		return lfcOpts.Opts, nil
	}

	// nothing set
	return lfcOpts.Opts, nil
}
