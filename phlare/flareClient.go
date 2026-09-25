package phlare

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mr-pmillz/gophlare/flareapi/astp"
	"github.com/mr-pmillz/gophlare/flareapi/fireworkv4"
	"github.com/mr-pmillz/gophlare/flareapi/flaretime"
	"github.com/mr-pmillz/gophlare/flareapi/tokens"
	"github.com/mr-pmillz/gophlare/internal/version"
	"github.com/mr-pmillz/gophlare/metrics"
	"github.com/mr-pmillz/gophlare/utils"
)

const (
	flareAPIBaseURL       = "https://api.flare.io"
	nullString            = "null"
	acceptHeaderTextPlain = "text/plain; charset=utf-8"
)

// DefaultGlobalSearchPageSize is the `size` sent to the global events search.
//
// Deliberately 5, not the documented maximum of 10: it was reduced from 10 for
// reliability and must stay there. Operators who know their tenant tolerates
// larger pages can raise it with --global-search-page-size to reduce requests.
// Quota is billed by search/result batch, so savings are not guaranteed.
const DefaultGlobalSearchPageSize = 5

// MaxGlobalSearchPageSize is the documented limit for the global events API.
const MaxGlobalSearchPageSize = 10

// apiTokenLifetime is how long a generated API token is reused. Flare documents
// a one-hour lifetime; refreshing after 45 minutes, as Flare's own Go SDK does,
// keeps requests from racing the expiry. The refresh_token_exp in the
// /tokens/generate response describes the refresh token, not the API token.
const apiTokenLifetime = 45 * time.Minute

// ClientOption customizes a FlareClient at construction. Options are applied
// before the token request, so BaseURL and the metrics recorder also cover
// /tokens/generate.
type ClientOption func(*FlareClient)

// WithMetricsRecorder attaches a usage recorder. Without one, no metrics are
// collected and every record call is a no-op.
func WithMetricsRecorder(r *metrics.Recorder) ClientOption {
	return func(fc *FlareClient) { fc.Metrics = r }
}

// WithBaseURL overrides the Flare API root, primarily so tests can point the
// client at an httptest server.
func WithBaseURL(baseURL string) ClientOption {
	return func(fc *FlareClient) {
		if baseURL != "" {
			fc.BaseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

// WithGlobalSearchPageSize sets the `size` for global events searches. A
// non-positive value is ignored so the default stands.
func WithGlobalSearchPageSize(size int) ClientOption {
	return func(fc *FlareClient) {
		if size > 0 {
			fc.GlobalSearchPageSize = size
		}
	}
}

// WithEntity presets the attribution label for requests that carry no domain
// parameter. Prefer ForEntity on an existing client.
func WithEntity(entity string) ClientOption {
	return func(fc *FlareClient) { fc.Entity = entity }
}

// NewFlareClient initializes and returns a new FlareClient with the provided API key, tenant ID, and timeout settings.
// Optional ClientOptions customize the base URL, metrics recorder, global search page size, and entity attribution.
func NewFlareClient(apiKey, userAgent string, tenantID, timeout int, opts ...ClientOption) (*FlareClient, error) {
	finalUserAgent := ""
	if userAgent != "" {
		finalUserAgent = userAgent
	} else {
		finalUserAgent = fmt.Sprintf("gophlare/%s", version.String())
	}

	fc := &FlareClient{
		Client:               NewHTTPClientWithTimeOut(false, timeout), // sets a default timeout of 10 minutes for queries that take a long time
		DefaultUserAgent:     finalUserAgent,
		TenantID:             tenantID,
		APIKey:               apiKey,
		ClientTimeout:        timeout,
		BaseURL:              flareAPIBaseURL,
		GlobalSearchPageSize: DefaultGlobalSearchPageSize,
	}
	// Applied before the token request so WithBaseURL and WithMetricsRecorder
	// take effect for /tokens/generate too.
	for _, opt := range opts {
		opt(fc)
	}

	if fc.GlobalSearchPageSize > MaxGlobalSearchPageSize {
		return nil, fmt.Errorf("global search page size must not exceed %d", MaxGlobalSearchPageSize)
	}

	flareGetTokenURL := fmt.Sprintf("%s/tokens/generate", fc.baseURL())

	// Flare documents the API key being sent verbatim in the Authorization
	// header. Content-Type must be JSON or the tenant_id scoping is ignored.
	headers := map[string]string{
		"Authorization": apiKey,
		"Content-Type":  "application/json",
	}

	// A zero tenant ID is omitted, which selects the user's default tenant.
	requestBody, err := json.Marshal(tokens.TokenGenerateRequest{TenantID: tenantID})
	if err != nil {
		return nil, utils.LogError(err)
	}

	tokenResp := &FlareAuthResponse{}
	started := time.Now()
	statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareGetTokenURL, "POST", tokenResp, headers, nil, requestBody)
	fc.record(metrics.EndpointTokenGenerate, metrics.EntityAuth, statusCode, respHeader, started, false)
	if err != nil {
		utils.LogWarningf("Failed to request JWT token from Flare API. Error: %s\n", err.Error())
		utils.LogWarningf("retrying...")
		started = time.Now()
		statusCode, respHeader, err = fc.Client.DoReqWithHeaders(flareGetTokenURL, "POST", tokenResp, headers, nil, requestBody)
		fc.record(metrics.EndpointTokenGenerate, metrics.EntityAuth, statusCode, respHeader, started, true)
		if err != nil {
			return nil, utils.LogError(err)
		}
	}
	if statusCode != 200 {
		return nil, fmt.Errorf("failed to obtain Flare API token")
	}

	fc.Token = &tokenResp.Token
	tokenExp := started.Add(apiTokenLifetime)
	fc.TokenExp = &tokenExp
	return fc, nil
}

// ForEntity returns a shallow copy of the client whose requests are attributed
// to entity. The receiver is not mutated, and the copy shares the underlying
// HTTP client and metrics recorder, so per-domain scoping costs nothing.
func (fc *FlareClient) ForEntity(entity string) *FlareClient {
	if fc == nil {
		return nil
	}
	scoped := *fc
	scoped.Entity = entity
	return &scoped
}

// record attributes one completed request to the metrics recorder. A nil
// recorder is a no-op. An empty entity falls back to the client's own Entity,
// which is how requests with no domain parameter get attributed.
func (fc *FlareClient) record(endpoint metrics.Endpoint, entity string, status int, respHeader http.Header, started time.Time, retry bool) {
	if fc == nil || fc.Metrics == nil {
		return
	}
	if entity == "" {
		entity = fc.Entity
	}
	fc.Metrics.Record(metrics.Call{
		Endpoint: endpoint,
		Entity:   entity,
		Status:   status,
		Duration: time.Since(started),
		Header:   respHeader,
		Retry:    retry,
	})
}

// baseURL preserves the default for SDK clients built with a struct literal.
func (fc *FlareClient) baseURL() string {
	if fc.BaseURL == "" {
		return flareAPIBaseURL
	}
	return fc.BaseURL
}

// pageSize returns the configured global search page size, guarding against a
// zero value on a FlareClient built without the constructor.
func (fc *FlareClient) pageSize() int {
	if fc.GlobalSearchPageSize > 0 {
		return fc.GlobalSearchPageSize
	}
	return DefaultGlobalSearchPageSize
}

// IsAPITokenExpired returns true if the API token has expired
func (fc *FlareClient) IsAPITokenExpired() bool {
	if fc.Token == nil || fc.TokenExp == nil {
		return true
	}
	return time.Now().After(*fc.TokenExp)
}

// RefreshAPIToken refreshes the API token if it has expired
func (fc *FlareClient) RefreshAPIToken() (*FlareClient, error) {
	if !fc.IsAPITokenExpired() {
		return fc, nil
	}
	utils.InfoLabelWithColorf("FLARE API TOKEN", "yellow", "API token expired, refreshing...")
	// Carry the current configuration across. Without this the refresh would
	// hand back a client with a fresh recorder, silently resetting every
	// counter mid-run, and would drop a test's BaseURL override.
	updatedFC, err := NewFlareClient(fc.APIKey, fc.DefaultUserAgent, fc.TenantID, fc.ClientTimeout,
		WithBaseURL(fc.BaseURL),
		WithMetricsRecorder(fc.Metrics),
		WithGlobalSearchPageSize(fc.GlobalSearchPageSize),
		WithEntity(fc.Entity),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	return updatedFC, nil
}

// ensureToken refreshes fc's API token in place once it has expired, so later
// requests made with fc, including the rest of a pagination loop, reuse it.
func (fc *FlareClient) ensureToken() error {
	if !fc.IsAPITokenExpired() {
		return nil
	}
	refreshed, err := fc.RefreshAPIToken()
	if err != nil {
		return err
	}
	fc.Token, fc.TokenExp = refreshed.Token, refreshed.TokenExp
	return nil
}

// QueryGlobalEvents performs a search for global events by domain and returns the results *FlareEventsGlobalSearchResults
func QueryGlobalEvents(fc *FlareClient, domain, outputDir, query, from, to string, severity, eventFilterTypes []string, searchStealerLogsByHostDomain, searchStealerLogsByWildcardHost bool) (*FlareEventsGlobalSearchResults, error) {
	results, err := fc.FlareEventsGlobalSearchByDomain(domain, outputDir, query, from, to, severity, eventFilterTypes, searchStealerLogsByHostDomain, searchStealerLogsByWildcardHost)
	if err != nil {
		return nil, utils.LogError(err)
	}
	return results, nil
}

// FlareRetrieveEventActivitiesByID retrieves event activities by their unique ID from the Flare API and returns the response or an error.
func (fc *FlareClient) FlareRetrieveEventActivitiesByID(uid string) (*FlareFireworkActivitiesIndexSourceIDv2Response, error) {
	if err := fc.ensureToken(); err != nil {
		return nil, err
	}
	// The UID goes in the query string: UIDs contain slashes, and Flare keeps the
	// /firework/v2/activities/{index}/{source}/{id} path form only for
	// backwards compatibility.
	flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/", fc.baseURL())
	headers := fc.defaultHeaders()
	params := map[string]string{"uid": uid}
	data := &FlareFireworkActivitiesIndexSourceIDv2Response{}

	started := time.Now()
	statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareGetEventActivitiesByIDURL, "GET", data, headers, params, nil)
	// No domain parameter here, so attribution comes from the client's Entity.
	fc.record(metrics.EndpointActivityByID, "", statusCode, respHeader, started, false)
	if err != nil {
		return nil, utils.LogError(err)
	}

	if statusCode == 401 {
		return nil, fmt.Errorf("received %d HTTP response code. Authorization failed. Check API request quota and try again later", statusCode)
	}
	if statusCode != 200 {
		return nil, fmt.Errorf("error retrieving flare event activities by ID, received non 200 HTTP response status code: %d", statusCode)
	}

	return data, nil
}

// FlareDownloadStealerLogZipFilesThatContainPasswords downloads specific password-related zip files from Flare's stealer log activities.
// It fetches logs such as "Passwords.txt" or "All Passwords.txt" if available, saves them to the output directory, and returns file paths.
// Returns a list of paths to downloaded files or an error in case of failures.
//
//nolint:goconst
func (fc *FlareClient) FlareDownloadStealerLogZipFilesThatContainPasswords(data *FlareFireworkActivitiesIndexSourceIDv2Response, outputDir string) ([]string, error) {
	filesToDownload := map[string]struct{}{
		"All Passwords.txt": {},
		"Passwords.txt":     {},
		"passwords.txt":     {},
		"Autofills.txt":     {},
	}
	downloadedFilePaths := make([]string, 0)
	for _, stealerLogsFile := range data.Activity.Data.Files {
		if _, exists := filesToDownload[stealerLogsFile]; exists {
			if err := fc.ensureToken(); err != nil {
				return nil, err
			}
			flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download", fc.baseURL(), data.Activity.Data.UID)
			headers := fc.defaultHeaders()
			headers["Accept"] = acceptHeaderTextPlain
			params := map[string]string{
				"i_agree_to_tos": "true",
			}

			outputFilePath := fmt.Sprintf("%s/flare-%s-%s.zip", outputDir, data.Activity.Data.Index, data.Activity.Data.ID)
			if exists, err := utils.Exists(outputFilePath); err == nil && exists {
				utils.InfoLabelf("FLARE STEALER LOGS", "Skipping %s, already downloaded", outputFilePath)
				downloadedFilePaths = append(downloadedFilePaths, outputFilePath)
				break
			}

			utils.InfoLabelWithColorf("FLARE STEALER LOGS", "green", "Downloading %s", flareGetEventActivitiesByIDURL)
			resp := &FlareStealerLogZipFileDownloadResponse{}
			started := time.Now()
			statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareGetEventActivitiesByIDURL, "GET", resp, headers, params, nil)
			fc.record(metrics.EndpointActivityDownload, "", statusCode, respHeader, started, false)
			if err != nil {
				return nil, utils.LogError(err)
			}
			if statusCode != 200 {
				return nil, fmt.Errorf("error retrieving flare event activities by ID, received non 200 HTTP response status code: %d", statusCode)
			}
			if resp.StealerLog.ExternalURL != "" {
				time.Sleep(time.Second * 4)
				err = downloadZip(resp.StealerLog.ExternalURL, outputFilePath, fc.DefaultUserAgent)
				if err != nil {
					return nil, utils.LogError(err)
				}
			}
			downloadedFilePaths = append(downloadedFilePaths, outputFilePath)
			break
		}
	}

	return downloadedFilePaths, nil
}

// FlareDownloadStealerLogPasswordFiles ... ToDo: Unused
// can also download files directly without downloading the entire zip by looping through data.Activity.Data.Files to see what files you wanna download.
// downloading the full zip and then looping through a temporary unzip dir is easier and reduces the number of API calls. blahzay blahzay blah
func (fc *FlareClient) FlareDownloadStealerLogPasswordFiles(data *FlareFireworkActivitiesIndexSourceIDv2Response, outputDir string, files []string) ([]string, error) {
	filesToDownload := map[string]struct{}{
		"All Passwords.txt": {},
		"Passwords.txt":     {},
		"passwords.txt":     {},
		"Autofills.txt":     {},
	}
	// append files to filesToDownload
	for _, file := range files {
		filesToDownload[file] = struct{}{}
	}
	downloadedFilePaths := make([]string, 0)
	for _, stealerLogsFile := range data.Activity.Data.Files {
		if _, exists := filesToDownload[stealerLogsFile]; exists {
			// flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download_file?file=%s", flareAPIBaseURL, data.Activity.Data.UID, stealerLogsFile)
			flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download_file", fc.baseURL(), data.Activity.Data.UID)
			utils.InfoLabelWithColorf("FLARE STEALER LOGS", "green", "Downloading %s", flareGetEventActivitiesByIDURL)
			if err := fc.ensureToken(); err != nil {
				return nil, err
			}
			headers := fc.defaultHeaders()
			headers["Accept"] = acceptHeaderTextPlain
			params := map[string]string{
				"file":           stealerLogsFile, // to download individual file, can use the file param and download_file endpoint
				"i_agree_to_tos": "true",
			}

			sanitizedFileName := utils.SanitizeString(stealerLogsFile)
			outputFilePath := fmt.Sprintf("%s/flare-%s-%s", outputDir, data.Activity.Data.ID, sanitizedFileName) // this has file extension

			started := time.Now()
			statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareGetEventActivitiesByIDURL, "GET", outputFilePath, headers, params, nil)
			fc.record(metrics.EndpointActivityDownloadFile, "", statusCode, respHeader, started, false)
			if err != nil {
				return nil, utils.LogError(err)
			}
			if statusCode != 200 {
				return nil, fmt.Errorf("error received non 200 HTTP response status code: %d", statusCode)
			}
			downloadedFilePaths = append(downloadedFilePaths, outputFilePath)
			break
		}
	}

	return downloadedFilePaths, nil
}

// FlareDownloadStealerLogCookieFiles downloads specified cookie files from Flare's stealer log activities and saves them locally.
// Returns a list of file paths for successfully downloaded files or an error in case of failures.
func (fc *FlareClient) FlareDownloadStealerLogCookieFiles(data *FlareFireworkActivitiesIndexSourceIDv2Response, outputDir string, files []string) ([]string, error) {
	filesToDownload := map[string]struct{}{
		"All Cookies.txt": {},
		"Cookies.txt":     {},
		"cookies.txt":     {},
	}
	// append files to filesToDownload
	for _, file := range files {
		filesToDownload[file] = struct{}{}
	}
	downloadedFilePaths := make([]string, 0)
	// can check data.Activity.Data.Cookies for cookies names that are high-value targets.
	for _, stealerLogsFile := range data.Activity.Data.Files {
		// flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download_file?file=%s", flareAPIBaseURL, data.Activity.Data.UID, stealerLogsFile)
		flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download_file", fc.baseURL(), data.Activity.Data.UID)
		utils.InfoLabelWithColorf("FLARE STEALER LOGS", "green", "Downloading %s", flareGetEventActivitiesByIDURL)
		if err := fc.ensureToken(); err != nil {
			return nil, err
		}
		headers := fc.defaultHeaders()
		headers["Accept"] = acceptHeaderTextPlain
		params := map[string]string{
			"file":           stealerLogsFile, // to download individual file, can use the file param and download_file endpoint
			"i_agree_to_tos": "true",
		}

		sanitizedFileName := utils.SanitizeString(stealerLogsFile)
		outputFilePath := fmt.Sprintf("%s/flare-%s-%s", outputDir, data.Activity.Data.ID, sanitizedFileName) // this has file extension

		started := time.Now()
		statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareGetEventActivitiesByIDURL, "GET", outputFilePath, headers, params, nil)
		fc.record(metrics.EndpointActivityDownloadFile, "", statusCode, respHeader, started, false)
		if err != nil {
			return nil, utils.LogError(err)
		}
		if statusCode != 200 {
			return nil, fmt.Errorf("error received non 200 HTTP response status code: %d", statusCode)
		}
		downloadedFilePaths = append(downloadedFilePaths, outputFilePath)
	}
	return downloadedFilePaths, nil
}

// parseSearchDate parses a --from/--to style date filter, which may be a date
// or a full timestamp, falling back to def when value is empty.
func parseSearchDate(value string, def time.Time) (flaretime.Time, error) {
	if value == "" {
		return flaretime.Time{Time: def}, nil
	}
	parsed, err := flaretime.Parse(value)
	if err != nil {
		return flaretime.Time{}, fmt.Errorf("invalid date filter %q: %w", value, err)
	}
	return parsed, nil
}

// isLastPage reports whether a `next` cursor marks the end of Flare's standard
// paging pattern. JSON null decodes to "".
func isLastPage(next string) bool {
	return next == "" || next == nullString
}

// FlareEventsGlobalSearchByDomain performs a global search in Flare's database for events related to a specified domain.
// It supports query customization, date range filters, and severity levels, aggregating results via pagination.
// Results are saved to a JSON file in the specified output directory for further analysis or storage.
// Returns aggregated search results or an error in case the operation fails.
//
//nolint:gocognit
//nolint:dupl
func (fc *FlareClient) FlareEventsGlobalSearchByDomain(domain, outputDir, query, from, to string, severity, eventFilterTypes []string, searchStealerLogsByHostDomain, searchStealerLogsByWildcardHost bool) (*FlareEventsGlobalSearchResults, error) {
	flareGlobalEventsSearchURL := fmt.Sprintf("%s/firework/v4/events/global/_search", fc.baseURL())
	allData := &FlareEventsGlobalSearchResults{}
	size := fc.pageSize()
	var queryString string
	switch {
	case query != "":
		queryString = query
	case searchStealerLogsByHostDomain:
		queryString = fmt.Sprintf("metadata.source:stealer_logs* AND features.domains:%s", domain)
	case searchStealerLogsByWildcardHost:
		queryString = fmt.Sprintf("metadata.source:stealer_logs* AND features.domains:*.%s", domain)
	default:
		queryString = fmt.Sprintf("metadata.source:stealer_logs* AND features.emails:*@%s", domain)
	}
	// Without a `from` date, search the last 2 years.
	fromDate, err := parseSearchDate(from, time.Now().UTC().AddDate(-2, 0, 0))
	if err != nil {
		return nil, err
	}
	// Without a `to` date, search up to the start of today, matching the --to
	// flag's default.
	toDate, err := parseSearchDate(to, time.Now().UTC().Truncate(24*time.Hour))
	if err != nil {
		return nil, err
	}
	postBody := &FlareEventsGlobalSearchBodyParams{
		Size: size,
		Filters: Filters{
			Type: eventFilterTypes, // https://api.docs.flare.io/api-reference/v4/endpoints/global-search#param-type
			EstimatedCreatedAt: EstimatedCreatedAt{
				Gte: fromDate,
				Lte: toDate,
			},
		},
	}
	if err := postBody.Query.FromQueryStringQuery(Query{QueryString: queryString}); err != nil {
		return nil, utils.LogError(err)
	}
	if len(severity) > 0 {
		// An array matches the listed severities exactly.
		severities := make(fireworkv4.FeedFiltersSeverity1, 0, len(severity))
		for _, sev := range severity {
			severities = append(severities, fireworkv4.Severity(sev))
		}
		if err := postBody.Filters.Severity.FromFeedFiltersSeverity1(severities); err != nil {
			return nil, utils.LogError(err)
		}
	}

	// progress reporter: emits a status line every 30s with the running count
	// so users can see the SDK is still working on long-running searches.
	var progressCount atomic.Int64
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				utils.InfoLabelWithColorf("FlareEventsGlobalSearch", "cyan",
					"still paginating, %d items collected so far",
					progressCount.Load())
			}
		}
	}()
	defer close(progressDone)

	// Retries are bounded per page and reset after a successful response.
	retries := 0

flarePaginate: //nolint:dupl
	for {
		// Long paginations outlive the API token, so check it for every page.
		if err := fc.ensureToken(); err != nil {
			return nil, err
		}
		headers := fc.defaultHeaders()
		// marshal each time for 'from' parameter pagination via data.Next
		postBodyJSON, err := json.Marshal(postBody)
		if err != nil {
			return nil, utils.LogError(err)
		}
		data := &FlareEventsGlobalSearchResults{}
		started := time.Now()
		statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareGlobalEventsSearchURL, "POST", data, headers, nil, postBodyJSON)
		fc.record(metrics.EndpointGlobalEventsSearch, domain, statusCode, respHeader, started, retries > 0)
		if err != nil {
			return nil, utils.LogError(err)
		}

		delay, err := searchRetryDelay(statusCode, retries)
		if err != nil {
			return nil, err
		}
		if delay > 0 {
			retries++
			utils.LogWarningf("Flare API returned %d, retry %d/%d in %s", statusCode, retries, maxSearchRetries, delay)
			time.Sleep(delay)
			continue
		}
		retries = 0

		if statusCode != 200 {
			return nil, fmt.Errorf("error retrieving flare leak db results, received non 200 HTTP response status code: %d", statusCode)
		}

		// Append the new data to allData
		allData.Items = append(allData.Items, data.Items...)
		progressCount.Store(int64(len(allData.Items)))

		// Check if we've reached the end of the results
		if isLastPage(data.Next) {
			break flarePaginate
		}
		// Update the 'from' parameter for the next request
		postBody.From = data.Next
		time.Sleep(1 * time.Second)
	}

	utils.InfoLabelWithColorf("FlareEventsGlobalSearch", "blue", "found %d hits for query: %s", len(allData.Items), queryString)
	// check if domain is empty string
	if domain == "" {
		// if domain was empty, this means a custom query was likely provided without a value provided for the domain flag. in this case generate a file-safe timestamp to be used in the output file name.
		domain = fmt.Sprintf("custom-query_%d", time.Now().Unix())
	}
	// write full events results data to json file
	if err := utils.WriteStructToJSONFile(allData, fmt.Sprintf("%s/flare-events-stealerlogs-emails-%s.json", outputDir, domain)); err != nil {
		return nil, utils.LogError(err)
	}

	return allData, nil
}

// FlareBulkCredentialLookup queries the Flare API in batches of 100 emails and aggregates results
func (fc *FlareClient) FlareBulkCredentialLookup(emails []string, outputDir string) (*FlareListByBulkAccountResponse, error) {
	const batchSize = 100 // the documented maximum accounts per request
	flareListByBulkAccountsURL := fmt.Sprintf("%s/astp/identities/by_accounts", fc.baseURL())

	// Result accumulator
	accumulatedResult := make(FlareListByBulkAccountResponse)

	// Process emails in batches
	for start := 0; start < len(emails); start += batchSize {
		// Compute batch range
		end := min(start+batchSize, len(emails))
		emailBatch := emails[start:end]

		// Make the batch request and accumulate results
		batchData, err := fc.fetchBatchData(flareListByBulkAccountsURL, emailBatch)
		if err != nil {
			return nil, err
		}

		// Merge batch result into the accumulated result
		accumulatedResult = mergeResults(accumulatedResult, batchData)
	}

	if err := utils.WriteStructToJSONFile(accumulatedResult, fmt.Sprintf("%s/flare-bulk-credential-lookup.json", outputDir)); err != nil {
		return nil, utils.LogError(err)
	}

	return &accumulatedResult, nil
}

// defaultHeaders extracts common headers for Flare API requests
func (fc *FlareClient) defaultHeaders() map[string]string {
	token := ""
	if fc.Token != nil {
		token = *fc.Token
	}

	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
		"Content-Type":  "application/json",
		"User-Agent":    fc.DefaultUserAgent,
	}
}

// fetchBatchData handles making a single batched API request and parsing the response
func (fc *FlareClient) fetchBatchData(url string, accounts []string) (FlareListByBulkAccountResponse, error) {
	if err := fc.ensureToken(); err != nil {
		return nil, err
	}
	headers := fc.defaultHeaders()
	postBody, err := json.Marshal(astp.ByAccountsRequest{Accounts: accounts})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	batchData := make(FlareListByBulkAccountResponse)
	started := time.Now()
	respStatus, respHeader, err := fc.Client.DoReqWithHeaders(url, "POST", &batchData, headers, nil, postBody)
	fc.record(metrics.EndpointBulkAccounts, metrics.EntityBulkEmails, respStatus, respHeader, started, false)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	if respStatus != 200 {
		return nil, fmt.Errorf("API request failed with status code %d", respStatus)
	}

	return batchData, nil
}

// mergeResults merges batch results into the total result
func mergeResults(main, batch FlareListByBulkAccountResponse) FlareListByBulkAccountResponse {
	for key, entry := range batch {
		if existing, exists := main[key]; exists {
			existing.Passwords = append(existing.Passwords, entry.Passwords...)
			main[key] = existing
		} else {
			main[key] = entry
		}
	}
	return main
}

// FlareSearchCookiesByDomain searches for leaked cookies associated with a specific domain in Flare's database.
// Results are aggregated via pagination, exported to a JSON file, and returned in the response.
// Accepts domain name, output directory path, cookie names, and paths for filtering the search.
// Returns a response containing leaked cookie data or an error in case of a failure.
//
//nolint:dupl
func (fc *FlareClient) FlareSearchCookiesByDomain(domain, outputDir string, cookieNames, paths []string) (*FlareSearchCookiesResponse, error) {
	flareSearchCookiesURL := fmt.Sprintf("%s/astp/v2/cookies/_search", fc.baseURL())
	allData := &FlareSearchCookiesResponse{}
	size := 500 // documented default 100, maximum 2000
	postBody := &FlareSearchCookiesBodyParams{
		Domain: domain,
		Size:   size,
		Names:  cookieNames,
		Paths:  paths,
		// Only return cookies that have not expired yet.
		ExpiresAfter: flaretime.Time{Time: time.Now()},
	}

	// progress reporter: emits a status line every 30s with the running count
	// so users can see the SDK is still working on long-running searches.
	var progressCount atomic.Int64
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				utils.InfoLabelWithColorf("FlareSearchCookies", "cyan",
					"still paginating, %d items collected so far",
					progressCount.Load())
			}
		}
	}()
	defer close(progressDone)

	// Retries are bounded per page and reset after a successful response.
	retries := 0

flarePaginate:
	for {
		// Long paginations outlive the API token, so check it for every page.
		if err := fc.ensureToken(); err != nil {
			return nil, err
		}
		headers := fc.defaultHeaders()
		// marshal each time for 'from' parameter pagination via data.Next
		postBodyJSON, err := json.Marshal(postBody)
		if err != nil {
			return nil, utils.LogError(err)
		}
		data := &FlareSearchCookiesResponse{}
		started := time.Now()
		statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareSearchCookiesURL, "POST", data, headers, nil, postBodyJSON)
		fc.record(metrics.EndpointASTPCookiesSearch, domain, statusCode, respHeader, started, retries > 0)
		if err != nil {
			return nil, utils.LogError(err)
		}

		delay, err := searchRetryDelay(statusCode, retries)
		if err != nil {
			return nil, err
		}
		if delay > 0 {
			retries++
			utils.LogWarningf("Flare API returned %d, retry %d/%d in %s", statusCode, retries, maxSearchRetries, delay)
			time.Sleep(delay)
			continue
		}
		retries = 0

		if statusCode != 200 {
			return nil, fmt.Errorf("error retrieving flare leak db results, received non 200 HTTP response status code: %d", statusCode)
		}

		// Append the new data to allData
		allData.Items = append(allData.Items, data.Items...)
		progressCount.Store(int64(len(allData.Items)))

		// Check if we've reached the end of the results
		if isLastPage(data.Next) {
			break flarePaginate
		}
		// Update the 'from' parameter for the next request
		postBody.From = data.Next
		time.Sleep(1 * time.Second)
	}

	if err := utils.WriteStructToJSONFile(allData, fmt.Sprintf("%s/flare-cookies-search-%s.json", outputDir, domain)); err != nil {
		return nil, utils.LogError(err)
	}

	return allData, nil
}

// FlareSearchCredentialsByDomainASTP searches for leaked credentials associated with a specific domain in Flare's database.
// This method aggregates results via pagination and exports the final data to JSON files in the specified output directory.
// Returns aggregated leaked credentials or an error if the operation fails.
//
//nolint:dupl
func (fc *FlareClient) FlareSearchCredentialsByDomainASTP(domain string) (*FlareSearchCredentialsASTP, error) {
	flareLeaksByDomainURL := fmt.Sprintf("%s/astp/v2/credentials/_search", fc.baseURL())
	allData := &FlareSearchCredentialsASTP{}
	// Flare's gateway times out at ~30s; latency on this endpoint scales
	// roughly linearly with page size. Empirically (worst-case slow day):
	//   size=100 → ~8s    size=200 → ~13s    size=300 → ~24s    size=500 → 504
	// 100 leaves >20s of headroom even on slow days; pagination handles
	// arbitrarily-large result sets via the existing Next cursor loop.
	postBody := &FlareSearchCredentialsBodyParams{
		Size: 100,
	}
	if err := postBody.Query.FromDomainQuery(FlareDomainQuery{Fqdn: domain}); err != nil {
		return nil, utils.LogError(err)
	}

	// progress reporter: emits a status line every 30s with the running count
	// so users can see the SDK is still working on long-running searches.
	var progressCount atomic.Int64
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				utils.InfoLabelWithColorf("FlareSearchCredentialsASTP", "cyan",
					"still paginating, %d items collected so far",
					progressCount.Load())
			}
		}
	}()
	defer close(progressDone)

	// Retries are bounded per page and reset after a successful response.
	retries := 0

flarePaginate:
	for {
		// Long paginations outlive the API token, so check it for every page.
		if err := fc.ensureToken(); err != nil {
			return nil, err
		}
		headers := fc.defaultHeaders()
		// marshal each time for 'from' parameter pagination via data.Next
		postBodyJSON, err := json.Marshal(postBody)
		if err != nil {
			return nil, utils.LogError(err)
		}
		data := &FlareSearchCredentialsASTP{}
		started := time.Now()
		statusCode, respHeader, err := fc.Client.DoReqWithHeaders(flareLeaksByDomainURL, "POST", data, headers, nil, postBodyJSON)
		fc.record(metrics.EndpointASTPCredentialsSearch, domain, statusCode, respHeader, started, retries > 0)
		if err != nil {
			return nil, utils.LogError(err)
		}

		delay, err := searchRetryDelay(statusCode, retries)
		if err != nil {
			return nil, err
		}
		if delay > 0 {
			retries++
			utils.LogWarningf("Flare API returned %d, retry %d/%d in %s", statusCode, retries, maxSearchRetries, delay)
			time.Sleep(delay)
			continue
		}
		retries = 0

		if statusCode != 200 {
			return nil, fmt.Errorf("error retrieving flare leak db results, received non 200 HTTP response status code: %d", statusCode)
		}

		// Append the new data to allData
		allData.Items = append(allData.Items, data.Items...)
		progressCount.Store(int64(len(allData.Items)))

		// Check if we've reached the end of the results
		if isLastPage(data.Next) {
			break flarePaginate
		}
		// Update the 'from' parameter for the next request
		postBody.From = data.Next
		time.Sleep(1 * time.Second)
	}

	return allData, nil
}

// HTTP timeouts bound individual attempts, not a pagination retry loop.
const maxSearchRetries = 5

func searchRetryDelay(status, retries int) (time.Duration, error) {
	var delay time.Duration
	switch status {
	case http.StatusTooManyRequests:
		delay = 10 * time.Second
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		delay = 15 * time.Second
	default:
		return 0, nil
	}
	if retries >= maxSearchRetries {
		return 0, fmt.Errorf("flare API returned %d after %d retries", status, retries)
	}
	return delay, nil
}
