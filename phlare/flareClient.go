package phlare

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/mr-pmillz/gophlare/utils"
	"time"
)

const (
	flareAPIBaseURL       = "https://api.flare.io"
	gophlareClientVersion = "v1.2.6"
	nullString            = "null"
	acceptHeaderTextPlain = "text/plain; charset=utf-8"
)

// NewFlareClient initializes and returns a new FlareClient with the provided API key, tenant ID, and timeout settings.
func NewFlareClient(apiKey, userAgent string, tenantID, timeout int) (*FlareClient, error) {
	c := NewHTTPClientWithTimeOut(false, timeout) // sets a default timeout of 10 minutes for queries that take a long time
	flareGetTokenURL := fmt.Sprintf("%s/tokens/generate", flareAPIBaseURL)
	finalUserAgent := ""
	if userAgent != "" {
		finalUserAgent = userAgent
	} else {
		finalUserAgent = fmt.Sprintf("gophlare/%s", gophlareClientVersion)
	}

	// Create the Authorization Basic header
	authString := fmt.Sprintf(":%s", apiKey) // ":" for empty username
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authString))

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Basic %s", encodedAuth),
		"Content-Type":  "application/json",
	}

	// Create the request body
	requestBody, err := json.Marshal(map[string]int{
		"tenant_id": tenantID,
	})
	if err != nil {
		return nil, utils.LogError(err)
	}

	tokenResp := &FlareAuthResponse{}
	statusCode, err := c.DoReq(flareGetTokenURL, "POST", tokenResp, headers, nil, requestBody)
	if err != nil {
		utils.LogWarningf("Failed to request JWT token from Flare API. Error: %s\n", err.Error())
		utils.LogWarningf("retrying...")
		statusCode, err = c.DoReq(flareGetTokenURL, "POST", tokenResp, headers, nil, requestBody)
		if err != nil {
			return nil, utils.LogError(err)
		}
	}
	if statusCode == 200 {
		return &FlareClient{
			Token:            &tokenResp.Token,
			Client:           c,
			DefaultUserAgent: finalUserAgent,
			TenantID:         tenantID,
			APIKey:           apiKey,
			TokenExp:         EpochToTime(tokenResp.RefreshTokenExp),
			ClientTimeout:    timeout,
		}, nil
	} else {
		return nil, fmt.Errorf("failed to obtain Flare API token")
	}
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
	updatedFC, err := NewFlareClient(fc.APIKey, fc.DefaultUserAgent, fc.TenantID, fc.ClientTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	return updatedFC, nil
}

// QueryGlobalEvents performs a search for global events by domain and returns the results *FlareEventsGlobalSearchResults
func QueryGlobalEvents(fc *FlareClient, domain, outputDir, query, from, to string, severity, eventFilterTypes []string) (*FlareEventsGlobalSearchResults, error) {
	results, err := fc.FlareEventsGlobalSearchByDomain(domain, outputDir, query, from, to, severity, eventFilterTypes)
	if err != nil {
		return nil, utils.LogError(err)
	}
	return results, nil
}

// FlareRetrieveEventActivitiesByID retrieves event activities by their unique ID from the Flare API and returns the response or an error.
func (fc *FlareClient) FlareRetrieveEventActivitiesByID(uid string) (*FlareFireworkActivitiesIndexSourceIDv2Response, error) {
	// initialize new FlareClient in case token has expired
	refreshedFC := &FlareClient{}
	// Check token expiry before making the request
	if fc.IsAPITokenExpired() {
		var err error
		refreshedFC, err = fc.RefreshAPIToken()
		if err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}
	} else {
		refreshedFC = fc
	}
	flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s", flareAPIBaseURL, uid)
	headers := refreshedFC.defaultHeaders()
	data := &FlareFireworkActivitiesIndexSourceIDv2Response{}

	statusCode, err := refreshedFC.Client.DoReq(flareGetEventActivitiesByIDURL, "GET", data, headers, nil, nil)
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
			flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download", flareAPIBaseURL, data.Activity.Data.UID)
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
			statusCode, err := fc.Client.DoReq(flareGetEventActivitiesByIDURL, "GET", resp, headers, params, nil)
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
	}
	// append files to filesToDownload
	for _, file := range files {
		filesToDownload[file] = struct{}{}
	}
	downloadedFilePaths := make([]string, 0)
	for _, stealerLogsFile := range data.Activity.Data.Files {
		if _, exists := filesToDownload[stealerLogsFile]; exists {
			// flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download_file?file=%s", flareAPIBaseURL, data.Activity.Data.UID, stealerLogsFile)
			flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download_file", flareAPIBaseURL, data.Activity.Data.UID)
			utils.InfoLabelWithColorf("FLARE STEALER LOGS", "green", "Downloading %s", flareGetEventActivitiesByIDURL)
			headers := fc.defaultHeaders()
			headers["Accept"] = acceptHeaderTextPlain
			params := map[string]string{
				"file":           stealerLogsFile, // to download individual file, can use the file param and download_file endpoint
				"i_agree_to_tos": "true",
			}

			sanitizedFileName := utils.SanitizeString(stealerLogsFile)
			outputFilePath := fmt.Sprintf("%s/flare-%s-%s", outputDir, data.Activity.Data.ID, sanitizedFileName) // this has file extension

			statusCode, err := fc.Client.DoReq(flareGetEventActivitiesByIDURL, "GET", outputFilePath, headers, params, nil)
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
		flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download_file", flareAPIBaseURL, data.Activity.Data.UID)
		utils.InfoLabelWithColorf("FLARE STEALER LOGS", "green", "Downloading %s", flareGetEventActivitiesByIDURL)
		headers := fc.defaultHeaders()
		headers["Accept"] = acceptHeaderTextPlain
		params := map[string]string{
			"file":           stealerLogsFile, // to download individual file, can use the file param and download_file endpoint
			"i_agree_to_tos": "true",
		}

		sanitizedFileName := utils.SanitizeString(stealerLogsFile)
		outputFilePath := fmt.Sprintf("%s/flare-%s-%s", outputDir, data.Activity.Data.ID, sanitizedFileName) // this has file extension

		statusCode, err := fc.Client.DoReq(flareGetEventActivitiesByIDURL, "GET", outputFilePath, headers, params, nil)
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

// getPastISO8601Date returns the ISO-8601 (RFC3339) timestamp X years prior to now
func getPastISO8601Date(yearsAgo int) string {
	// Get the current UTC time
	now := time.Now().UTC()
	// Subtract 4 years from the current date
	pastTime := now.AddDate(-yearsAgo, 0, 0)
	// Format the past date in ISO-8601 (RFC3339 format)
	return pastTime.Format(time.RFC3339)
}

// FlareEventsGlobalSearchByDomain performs a global search in Flare's database for events related to a specified domain.
// It supports query customization, date range filters, and severity levels, aggregating results via pagination.
// Results are saved to a JSON file in the specified output directory for further analysis or storage.
// Returns aggregated search results or an error in case the operation fails.
//
//nolint:gocognit
func (fc *FlareClient) FlareEventsGlobalSearchByDomain(domain, outputDir, query, from, to string, severity, eventFilterTypes []string) (*FlareEventsGlobalSearchResults, error) {
	flareGlobalEventsSearchURL := fmt.Sprintf("%s/firework/v4/events/global/_search", flareAPIBaseURL)
	headers := fc.defaultHeaders()
	allData := &FlareEventsGlobalSearchResults{}
	size := 10
	var queryString string
	if query != "" {
		queryString = query
	} else {
		queryString = fmt.Sprintf("metadata.source:stealer_logs* AND features.emails:*@%s", domain)
	}
	var fromDate string
	if from != "" {
		fromDate = from
	} else {
		fromDate = getPastISO8601Date(2) // if no `from` date is provided, default to 2 years ago
	}
	var toDate string
	if to != "" {
		toDate = to
	} else {
		toDate = todaysDate() // if not `to` date is provided, default to today's date
	}
	postBody := &FlareEventsGlobalSearchBodyParams{
		Query: Query{
			Type:        "query_string",
			QueryString: queryString,
		},
		Size: size,
		Filters: Filters{
			Severity: severity,
			Type:     eventFilterTypes, // https://api.docs.flare.io/api-reference/v4/endpoints/global-search#param-type
			EstimatedCreatedAt: EstimatedCreatedAt{
				Gte: fromDate,
				Lte: toDate,
			},
		},
	}

flarePaginate:
	for {
		// marshal each time for 'from' parameter pagination via *data.Next
		postBodyJSON, err := json.Marshal(postBody)
		if err != nil {
			return nil, utils.LogError(err)
		}
		data := &FlareEventsGlobalSearchResults{}
		statusCode, err := fc.Client.DoReq(flareGlobalEventsSearchURL, "POST", data, headers, nil, postBodyJSON)
		if err != nil {
			return nil, utils.LogError(err)
		}

		if statusCode == 429 {
			time.Sleep(10 * time.Second)
			continue
		}

		if statusCode != 200 {
			return nil, fmt.Errorf("error retrieving flare leak db results, received non 200 HTTP response status code: %d", statusCode)
		}

		// Append the new data to allData
		allData.Items = append(allData.Items, data.Items...)

		// Check if we've reached the end of the results
		switch {
		case data.Next == nil:
			break flarePaginate
		case *data.Next == "":
			break flarePaginate
		case *data.Next == nullString:
			break flarePaginate
		default:
			// Update the 'from' parameter for the next request
			postBody.From = *data.Next
			// utils.InfoLabelWithColorf("Flare Search Credentials", "blue", "found %d hits for %s", len(data.Items), domain)
			time.Sleep(1 * time.Second)
		}
	}

	utils.InfoLabelWithColorf("FlareEventsGlobalSearch", "blue", "found %d hits for query: %s", len(allData.Items), queryString)
	// write full events results data to json file
	if err := utils.WriteStructToJSONFile(allData, fmt.Sprintf("%s/flare-events-stealerlogs-emails-%s.json", outputDir, domain)); err != nil {
		return nil, utils.LogError(err)
	}

	return allData, nil
}

// FlareBulkCredentialLookup queries the Flare API in batches of 100 emails and aggregates results
func (fc *FlareClient) FlareBulkCredentialLookup(emails []string, outputDir string) (*FlareListByBulkAccountResponse, error) {
	const batchSize = 100
	flareListByBulkAccountsURL := fmt.Sprintf("%s/leaksdb/identities/by_accounts", flareAPIBaseURL)
	headers := fc.defaultHeaders()

	// Result accumulator
	accumulatedResult := make(FlareListByBulkAccountResponse)

	// Process emails in batches
	for start := 0; start < len(emails); start += batchSize {
		// Compute batch range
		end := min(start+batchSize, len(emails))
		emailBatch := emails[start:end]

		// Make the batch request and accumulate results
		batchData, err := fc.fetchBatchData(flareListByBulkAccountsURL, headers, emailBatch)
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
func (fc *FlareClient) fetchBatchData(url string, headers map[string]string, accounts []string) (FlareListByBulkAccountResponse, error) {
	payload := map[string]interface{}{
		"accounts": accounts,
	}

	postBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	batchData := make(FlareListByBulkAccountResponse)
	respStatus, err := fc.Client.DoReq(url, "POST", &batchData, headers, nil, postBody)
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
func (fc *FlareClient) FlareSearchCookiesByDomain(domain, outputDir string, cookieNames, paths []string) (*FlareSearchCookiesResponse, error) {
	flareSearchCookiesURL := fmt.Sprintf("%s/leaksdb/v2/cookies/_search", flareAPIBaseURL)
	headers := fc.defaultHeaders()
	allData := &FlareSearchCookiesResponse{}
	size := 500
	// current date for ExpiresAfter param
	expiresAfter := time.Now().Format(time.RFC3339)
	postBody := &FlareSearchCookiesBodyParams{
		Domain: domain,
		Size:   size,
		Names:  cookieNames,
		Paths:  paths,
		// ImportedAfter: "",
		ExpiresAfter: expiresAfter,
	}

flarePaginate:
	for {
		// marshal each time for 'from' parameter pagination via *data.Next
		postBodyJSON, err := json.Marshal(postBody)
		if err != nil {
			return nil, utils.LogError(err)
		}
		data := &FlareSearchCookiesResponse{}
		statusCode, err := fc.Client.DoReq(flareSearchCookiesURL, "POST", data, headers, nil, postBodyJSON)
		if err != nil {
			return nil, utils.LogError(err)
		}

		if statusCode == 429 {
			time.Sleep(10 * time.Second)
			continue
		}

		if statusCode != 200 {
			return nil, fmt.Errorf("error retrieving flare leak db results, received non 200 HTTP response status code: %d", statusCode)
		}

		// Append the new data to allData
		allData.Items = append(allData.Items, data.Items...)

		// Check if we've reached the end of the results
		switch {
		case data.Next == nil:
			break flarePaginate
		case *data.Next == "":
			break flarePaginate
		case *data.Next == nullString:
			break flarePaginate
		default:
			// Update the 'from' parameter for the next request
			postBody.From = *data.Next
			// utils.InfoLabelWithColorf("Flare Search Credentials", "blue", "found %d hits for %s", len(data.Items), domain)
			time.Sleep(1 * time.Second)
		}
	}

	if err := utils.WriteStructToJSONFile(allData, fmt.Sprintf("%s/flare-cookies-search-%s.json", outputDir, domain)); err != nil {
		return nil, utils.LogError(err)
	}

	return allData, nil
}

// FlareLeakedCredentialsByDomain searches for leaked credentials associated with a specific domain in Flare's database.
// This method aggregates results via pagination and exports the final data to JSON files in the specified output directory.
// Returns aggregated leaked credentials or an error if the operation fails.
func (fc *FlareClient) FlareLeakedCredentialsByDomain(domain string) (*FlareSearchCredentials, error) {
	flareLeaksByDomainURL := fmt.Sprintf("%s/leaksdb/v2/credentials/_search", flareAPIBaseURL)
	headers := fc.defaultHeaders()
	allData := &FlareSearchCredentials{}
	size := "10000"
	postBody := &FlareSearchCredentialsBodyParams{
		Size: size,
		Query: FlareDomainQuery{
			Type: "domain",
			Fqdn: domain,
		},
	}

flarePaginate:
	for {
		// marshal each time for 'from' parameter pagination via *data.Next
		postBodyJSON, err := json.Marshal(postBody)
		if err != nil {
			return nil, utils.LogError(err)
		}
		data := &FlareSearchCredentials{}
		statusCode, err := fc.Client.DoReq(flareLeaksByDomainURL, "POST", data, headers, nil, postBodyJSON)
		if err != nil {
			return nil, utils.LogError(err)
		}

		if statusCode == 429 {
			time.Sleep(10 * time.Second)
			continue
		}

		if statusCode != 200 {
			return nil, fmt.Errorf("error retrieving flare leak db results, received non 200 HTTP response status code: %d", statusCode)
		}

		// Append the new data to allData
		allData.Items = append(allData.Items, data.Items...)

		// Check if we've reached the end of the results
		switch {
		case data.Next == nil:
			break flarePaginate
		case *data.Next == "":
			break flarePaginate
		case *data.Next == nullString:
			break flarePaginate
		default:
			// Update the 'from' parameter for the next request
			postBody.From = *data.Next
			// utils.InfoLabelWithColorf("Flare Search Credentials", "blue", "found %d hits for %s", len(data.Items), domain)
			time.Sleep(1 * time.Second)
		}
	}

	return allData, nil
}
