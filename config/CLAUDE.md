# CLAUDE.md - config/

Configuration loading package.

## Structure

- **config.go** — `GoPhlareConfig` struct with nested `APIKeys` (FLARE_API string, FLARE_TENANT_ID int). `LoadAPIKeys()` unmarshals from viper. `NewGoPhlareConfig()` is the library-usage constructor.
- **config.yaml** — Example/working config file. Contains real API keys and credentials — **do not commit changes to this file**.

## Config YAML Format

Config keys are UPPER_SNAKE_CASE and map to CLI flags via viper. Multi-value fields use YAML block scalars (`|-`) with one value per line. The `API_KEYS` section is nested.
