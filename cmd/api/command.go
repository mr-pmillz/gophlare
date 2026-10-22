package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mr-pmillz/gophlare/flareapi"
	"github.com/mr-pmillz/gophlare/internal/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type options struct {
	apiKey     string
	token      string
	tenantID   int
	baseURL    string
	timeout    time.Duration
	format     string
	columns    []string
	wide       bool
	outputFile string
	all        bool
	maxPages   int
	pageDelay  time.Duration
}

func NewCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "api", Short: "Call every documented Firework v2, v3 and v4 endpoint",
		SilenceUsage: true,
	}
	settings := addFlags(command)
	list := &cobra.Command{
		Use: "list", Short: "List all supported API operations (no authentication required)", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			data, err := json.Marshal(flareapi.Operations())
			if err != nil {
				return err
			}
			return output.Write(command.OutOrStdout(), data, settings.outputOptions())
		},
	}
	describe := &cobra.Command{
		Use: "describe VERSION OPERATION_ID", Short: "Show an operation's parameters and body schema", Args: cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, arguments []string) error {
			operation, err := flareapi.FindOperation(arguments[0], arguments[1])
			if err != nil {
				return err
			}
			return json.NewEncoder(command.OutOrStdout()).Encode(operation)
		},
	}
	command.AddCommand(list, describe)
	for _, version := range []string{"v2", "v3", "v4"} {
		versionCommand := &cobra.Command{Use: version, Short: "Firework " + version + " operations"}
		for _, operation := range flareapi.Operations() {
			if operation.Version == version {
				child := operationCommand(operation, settings)
				child.Use = operation.ID
				child.Aliases = []string{strings.ReplaceAll(operation.ID, "_", "-")}
				versionCommand.AddCommand(child)
			}
		}
		command.AddCommand(versionCommand)
	}
	return command
}

func addFlags(command *cobra.Command) *options {
	settings := &options{}
	flags := command.PersistentFlags()
	flags.StringVar(&settings.apiKey, "api-key", "", "Flare API key (prefer GOFLARE_API_KEY or API_KEYS.FLARE_API in config)")
	flags.StringVar(&settings.token, "api-token", "", "Existing bearer token (or GOFLARE_API_TOKEN); skips token generation")
	flags.IntVar(&settings.tenantID, "auth-tenant-id", 0, "Tenant to authenticate to (0 selects your default tenant)")
	flags.StringVar(&settings.baseURL, "base-url", flareapi.DefaultBaseURL, "Flare API server")
	flags.DurationVar(&settings.timeout, "timeout", time.Minute, "HTTP request timeout")
	flags.StringVarP(&settings.format, "format", "f", "table", "Output format: table or json")
	flags.StringSliceVar(&settings.columns, "columns", nil, "Table columns, comma-separated; supports nested keys such as metadata.uid")
	flags.BoolVar(&settings.wide, "wide", false, "Do not truncate table cells")
	flags.StringVar(&settings.outputFile, "output-file", "", "Write raw response to a new file (0600); use - for stdout")
	flags.BoolVar(&settings.all, "all", false, "Collect cursor pages into one items array (may consume API quota)")
	flags.IntVar(&settings.maxPages, "max-pages", 1000, "Maximum pages with --all; the last pagination cursor is retained")
	flags.DurationVar(&settings.pageDelay, "page-delay", time.Second, "Delay between pages with --all")
	return settings
}

func (settings *options) outputOptions() output.Options {
	return output.Options{Format: settings.format, Columns: settings.columns, Wide: settings.wide}
}

func operationCommand(operation flareapi.Operation, settings *options) *cobra.Command {
	short := operation.Summary
	if short == "" {
		short = operation.Method + " " + operation.Path
	}
	long := short + "\n\n" + operation.Method + " " + operation.Path + "\nOperation: " + operation.ID
	if operation.BodySchema != "" {
		long += "\nJSON body schema: " + operation.BodySchema
	}
	if operation.Deprecated {
		long += "\nDeprecated upstream; retained for API parity."
	}
	command := &cobra.Command{Use: operation.ID, Short: short, Long: long, Args: cobra.NoArgs, SilenceUsage: true}
	for _, parameter := range operation.Parameters {
		description := parameter.In + " parameter: " + parameter.Name + " (" + parameter.Type + ")"
		if parameter.Required {
			description += " [required]"
		}
		if parameter.Description != "" {
			description += "; " + parameter.Description
		}
		if parameter.Type == "array" {
			command.Flags().StringArray(parameterFlag(parameter.Name), nil, description+"; repeat for multiple values")
		} else {
			command.Flags().String(parameterFlag(parameter.Name), "", description)
		}
	}
	if operation.HasBody {
		command.Flags().String("body", "", "JSON request body, @filename, or - to read stdin")
	}
	command.RunE = func(command *cobra.Command, _ []string) error {
		return runOperation(command, operation, settings)
	}
	return command
}

func parameterFlag(name string) string {
	return strings.ReplaceAll(strings.TrimSuffix(name, "[]"), "_", "-")
}

func readRequest(command *cobra.Command, operation flareapi.Operation) (flareapi.Request, error) {
	input := flareapi.Request{Parameters: make(map[string]json.RawMessage)}
	for _, parameter := range operation.Parameters {
		name := parameterFlag(parameter.Name)
		if !command.Flags().Changed(name) {
			continue
		}
		var value any
		var err error
		if parameter.Type == "array" {
			values, flagError := command.Flags().GetStringArray(name)
			if flagError != nil {
				return input, flagError
			}
			items := make([]any, 0, len(values))
			for _, item := range values {
				parsed, parseError := parseParameter(item, parameter.ItemType)
				if parseError != nil {
					return input, fmt.Errorf("--%s: %w", name, parseError)
				}
				items = append(items, parsed)
			}
			value = items
		} else {
			text, flagError := command.Flags().GetString(name)
			if flagError != nil {
				return input, flagError
			}
			value, err = parseParameter(text, parameter.Type)
		}
		if err != nil {
			return input, fmt.Errorf("--%s: %w", name, err)
		}
		input.Parameters[parameter.Name], err = json.Marshal(value)
		if err != nil {
			return input, err
		}
	}
	if operation.HasBody {
		body, err := command.Flags().GetString("body")
		if err != nil {
			return input, err
		}
		switch {
		case body == "-":
			input.Body, err = io.ReadAll(command.InOrStdin())
		case strings.HasPrefix(body, "@"):
			input.Body, err = os.ReadFile(strings.TrimPrefix(body, "@"))
		default:
			input.Body = []byte(body)
		}
		if err != nil {
			return input, fmt.Errorf("read request body: %w", err)
		}
	}
	return input, nil
}

func parseParameter(value, kind string) (any, error) {
	switch kind {
	case "integer":
		return strconv.ParseInt(value, 10, 64)
	case "number":
		return strconv.ParseFloat(value, 64)
	case "boolean":
		return strconv.ParseBool(value)
	case "object":
		var object map[string]any
		err := json.Unmarshal([]byte(value), &object)
		return object, err
	default:
		return value, nil
	}
}

func runOperation(command *cobra.Command, operation flareapi.Operation, settings *options) error {
	if settings.format != "json" && settings.format != "table" {
		return fmt.Errorf("unsupported format %q (use table or json)", settings.format)
	}
	if settings.timeout <= 0 || settings.maxPages <= 0 || settings.pageDelay < 0 {
		return fmt.Errorf("timeout and max-pages must be positive; page-delay must be non-negative")
	}
	input, err := readRequest(command, operation)
	if err != nil {
		return err
	}
	if _, err := operation.BuildRequest(command.Context(), flareapi.DefaultBaseURL, input); err != nil {
		return err
	}
	client, err := flareapi.NewClient(settings.clientConfig(command))
	if err != nil {
		return err
	}
	if settings.outputFile != "" {
		return download(command, client, operation, input, settings)
	}
	var response *flareapi.Response
	if settings.all {
		response, err = client.Collect(command.Context(), operation, input, settings.maxPages, settings.pageDelay)
	} else {
		response, err = client.Call(command.Context(), operation, input)
	}
	if err != nil {
		return err
	}
	if settings.format == "table" {
		printCursor(command, operation, response.Body)
	}
	format := settings.outputOptions()
	format.RootKey = operation.ResponseKey
	return output.Write(command.OutOrStdout(), response.Body, format)
}

func printCursor(command *cobra.Command, operation flareapi.Operation, body []byte) {
	field, value, err := operation.NextCursor(body)
	if err != nil || value == "" {
		return
	}
	parameter := operation.PageCursors[field]
	resume := "--" + parameterFlag(parameter)
	if operation.PageIn == "body" {
		resume = "the JSON body's " + parameter + " field"
	}
	fmt.Fprintf(command.ErrOrStderr(), "More results available; %s=%q (use --all or %s).\n", field, value, resume)
}

func (settings *options) clientConfig(command *cobra.Command) flareapi.Config {
	apiKey := settings.apiKey
	if !command.Flags().Changed("api-key") {
		apiKey = os.Getenv("GOFLARE_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("FLARE_API_KEY")
		}
		if apiKey == "" {
			apiKey = viper.GetString("API_KEYS.FLARE_API")
		}
	}
	token := settings.token
	if !command.Flags().Changed("api-token") {
		token = os.Getenv("GOFLARE_API_TOKEN")
	}
	tenantID := settings.tenantID
	if !command.Flags().Changed("auth-tenant-id") {
		tenantID = viper.GetInt("API_KEYS.FLARE_TENANT_ID")
	}
	return flareapi.Config{APIKey: apiKey, Token: token, TenantID: tenantID, BaseURL: settings.baseURL, Timeout: settings.timeout}
}

func download(command *cobra.Command, client *flareapi.Client, operation flareapi.Operation, input flareapi.Request, settings *options) error {
	return writeFile(command, settings.outputFile, func() (io.ReadCloser, error) {
		if settings.all {
			response, err := client.Collect(command.Context(), operation, input, settings.maxPages, settings.pageDelay)
			if err != nil {
				return nil, err
			}
			return io.NopCloser(bytes.NewReader(response.Body)), nil
		}
		response, err := client.Execute(command.Context(), operation, input)
		if err != nil {
			return nil, err
		}
		return response.Body, nil
	})
}

func writeFile(command *cobra.Command, path string, response func() (io.ReadCloser, error)) error {
	if path == "-" {
		reader, err := response()
		if err != nil {
			return err
		}
		_, copyError := io.Copy(command.OutOrStdout(), reader)
		return errors.Join(copyError, reader.Close())
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("prepare output file: %w", err)
	}
	reader, err := response()
	if err != nil {
		return errors.Join(err, file.Close(), os.Remove(path))
	}
	_, copyError := io.Copy(file, reader)
	if err := errors.Join(copyError, reader.Close(), file.Close()); err != nil {
		return fmt.Errorf("incomplete download in %s: %w", path, err)
	}
	return nil
}
