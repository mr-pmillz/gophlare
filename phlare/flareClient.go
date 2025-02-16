package phlare

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	valid "github.com/asaskevich/govalidator"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/schollz/progressbar/v3"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	flareAPIBaseURL       = "https://api.flare.io"
	gophlareClientVersion = "v1.0.3"
	nullString            = "null"
)

// NewFlareClient ...
func NewFlareClient(apiKey string, tenantID int) (*FlareClient, error) {
	c := NewHTTPClientWithTimeOut(false, 600) // sets a timeout of 10 minutes for queries that take a long time
	flareGetTokenURL := fmt.Sprintf("%s/tokens/generate", flareAPIBaseURL)

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
		userAgent := fmt.Sprintf("gophlare/%s", gophlareClientVersion)
		return &FlareClient{Token: tokenResp.Token, Client: c, DefaultUserAgent: userAgent}, nil
	} else {
		return nil, fmt.Errorf("failed to obtain Flare API token")
	}
}

// DownloadAllStealerLogPasswordFiles ...
func DownloadAllStealerLogPasswordFiles(opts *Options, scope *Scope) error {
	flareOutputDir := fmt.Sprintf("%s/breach_data/stealer_logs", opts.Output)
	if err := os.MkdirAll(flareOutputDir, 0750); err != nil {
		return utils.LogError(err)
	}

	fc, err := NewFlareClient(opts.APIKeys.APIKeys.FlareAPI, opts.APIKeys.APIKeys.FlareTenantID)
	if err != nil {
		return utils.LogError(err)
	}

	allCSVFiles := make([]string, 0)
	for _, domain := range scope.Domains {
		utils.InfoLabelWithColorf("FLARE", "cyan", "Checking Stealer Logs for %s", domain)

		results, err := queryGlobalEvents(fc, domain, flareOutputDir, opts.Query, opts.Years)
		if err != nil {
			return err
		}
		numResults := len(results.Items)
		if numResults == 0 {
			utils.InfoLabelWithColorf("FLARE", "yellow", "No Stealer Logs found for %s", domain)
			continue
		}
		utils.InfoLabelWithColorf("FLARE", "green", "Got %d hits from the Flare Stealer Logs", numResults)

		allFlareStealerLogCredentials, err := downloadZipFilesAndProcessPasswordResults(results, fc, opts.MaxZipFilesToDownload, flareOutputDir, domain, scope.UserIDFormats, opts.KeepZipFiles)
		if err != nil {
			return err
		}

		csvFileName, err := writeCredentialsToCSV(allFlareStealerLogCredentials, flareOutputDir, domain)
		if err != nil {
			return err
		}

		allCSVFiles = append(allCSVFiles, csvFileName)
	}

	if err := exportCSVToExcel(allCSVFiles, flareOutputDir); err != nil {
		return err
	}

	utils.InfoLabelWithColorf("FLARE", "blue", "Finished downloading all stealer log zip files from Flare that contain passwords")
	return nil
}

// queryGlobalEvents performs a search for global events by domain
func queryGlobalEvents(fc *FlareClient, domain, outputDir, query string, years int) (*FlareEventsGlobalSearchResults, error) {
	results, err := fc.FlareEventsGlobalSearchByDomain(domain, outputDir, query, years)
	if err != nil {
		return nil, utils.LogError(err)
	}
	return results, nil
}

// downloadZipFilesAndProcessPasswordResults processes the results, downloading and parsing necessary files
func downloadZipFilesAndProcessPasswordResults(results *FlareEventsGlobalSearchResults, fc *FlareClient, limit int, outputDir, domain string, userIDFormats []string, keepZips bool) ([]FlareStealerLogsCredential, error) {
	allDownloadedFiles, allFlareStealerLogCredentials := make([]string, 0), make([]FlareStealerLogsCredential, 0)
	count := 0

	for _, result := range results.Items {
		if !isStealerLog(result.Metadata.Type) {
			continue
		}
		if limitReached(count, limit) {
			break
		}
		count++

		data, err := fc.FlareRetrieveEventActivitiesByID(result.Metadata.UID)
		if err != nil {
			return nil, utils.LogError(err)
		}

		downloadedFiles, err := fc.FlareDownloadStealerLogZipFilesThatContainPasswords(data, outputDir)
		if err != nil {
			utils.LogWarningf("Failed to download all Stealer Logs for %s: %s\n", result.Metadata.UID, err.Error())
			continue
		}
		allDownloadedFiles = append(allDownloadedFiles, downloadedFiles...)
	}

	parsedCredentials, allLiveCookieBros, allHighValueCookieBros, err := parseDownloadedFilesForPasswordsAndCookies(allDownloadedFiles, userIDFormats, domain)
	if err != nil {
		return nil, err
	}
	allFlareStealerLogCredentials = append(allFlareStealerLogCredentials, parsedCredentials...)

	// write allLiveCookieBros to JSON file
	cookieBroJSONFileName := fmt.Sprintf("%s/flare-stealer-logs-cookie-bro.json", outputDir)
	if err = utils.WriteStructToJSONFile(allLiveCookieBros, cookieBroJSONFileName); err != nil {
		return nil, utils.LogError(err)
	}

	// write allLiveCookieBros to JSON file
	highValueCookieBroJSONFileName := fmt.Sprintf("%s/flare-stealer-logs-high-value-cookie-bro.json", outputDir)
	if err = utils.WriteStructToJSONFile(allHighValueCookieBros, highValueCookieBroJSONFileName); err != nil {
		return nil, utils.LogError(err)
	}

	if !keepZips {
		for _, downloadedFile := range allDownloadedFiles {
			if err = os.Remove(downloadedFile); err != nil {
				utils.LogWarningf("Failed to remove downloaded file: %s\n", downloadedFile)
				continue
			}
		}
	}

	return UniqueCredentials(allFlareStealerLogCredentials), nil
}

// isStealerLog checks if the metadata type is a "stealer_log" or "bot"
func isStealerLog(mediaType string) bool {
	return mediaType == "stealer_log" || mediaType == "bot"
}

// limitReached checks if the process count has reached the specified limit
func limitReached(count, limit int) bool {
	return limit != 0 && count >= limit
}

// parseDownloadedFilesForPasswordsAndCookies parses downloaded files to extract credentials
func parseDownloadedFilesForPasswordsAndCookies(files, userIDFormats []string, domain string) ([]FlareStealerLogsCredential, []CookieBro, []CookieBro, error) {
	allParsedCredentials := make([]FlareStealerLogsCredential, 0)
	allCookieBros := make([]CookieBro, 0)
	allHighValueCookieBros := make([]CookieBro, 0)
	// by default when downloading the zips, process the password files for the in-scope domain
	filesToParse := map[string]struct{}{
		"All Passwords.txt": {},
		"Passwords.txt":     {},
		"passwords.txt":     {},
	}

	for _, file := range files {
		unzippedFiles, tempDir, err := utils.UnzipToTemp(file)
		if err != nil {
			return nil, nil, nil, utils.LogError(err)
		}

		for _, unzippedFile := range unzippedFiles {
			if _, exists := filesToParse[filepath.Base(unzippedFile)]; exists {
				// debug statement, todo: add in verbose option to print this...
				utils.InfoLabelWithColorf("FLARE", "green", "Parsing in-scope domain creds: %s", unzippedFile)
				credentials, err := parseCredentialsFile(unzippedFile, domain, userIDFormats)
				if err != nil {
					return nil, nil, nil, utils.LogError(err)
				}
				allParsedCredentials = append(allParsedCredentials, credentials...)
			}
			// check for cookie files
			if strings.Contains(strings.ToLower(unzippedFile), "cookie") {
				// todo: map filename to cookies struct so that when writing cookies to a file, can write cookies to smaller individual files corresponding to relevant stealer log index.
				liveCookies, highValueCookies, err := ParseCookieFile(unzippedFile)
				if err != nil {
					return nil, nil, nil, utils.LogError(err)
				}
				// map live cookies to cookie bro format struct
				cookieBros := MapCookiesToCookieBro(liveCookies)
				// append cookieBros to allCookieBros
				allCookieBros = append(allCookieBros, cookieBros...)

				highValueCookieBros := MapCookiesToCookieBro(highValueCookies)
				allHighValueCookieBros = append(allHighValueCookieBros, highValueCookieBros...)
			}
		}

		if err := os.RemoveAll(tempDir); err != nil {
			return nil, nil, nil, utils.LogError(err)
		}
	}
	return allParsedCredentials, allCookieBros, allHighValueCookieBros, nil
}

// writeCredentialsToCSV writes credentials to a CSV file
func writeCredentialsToCSV(credentials []FlareStealerLogsCredential, outputDir, domain string) (string, error) {
	fileName := fmt.Sprintf("%s/flare-stealer-logs-%s.csv", outputDir, domain)
	if err := utils.WriteStructToCSVFile(credentials, fileName); err != nil {
		return "", utils.LogError(err)
	}
	return fileName, nil
}

// exportCSVToExcel consolidates CSV files into an Excel report
func exportCSVToExcel(csvFiles []string, outputDir string) error {
	excelFileName := fmt.Sprintf("%s/flare-stealer-logs.xlsx", outputDir)
	if err := utils.CSVsToExcel(csvFiles, excelFileName); err != nil {
		return utils.LogError(err)
	}
	return nil
}

// FlareRetrieveEventActivitiesByID ...
func (fc *FlareClient) FlareRetrieveEventActivitiesByID(uid string) (*FlareFireworkActivitiesIndexSourceIDv2Response, error) {
	flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s", flareAPIBaseURL, uid)
	headers := fc.defaultHeaders()
	data := &FlareFireworkActivitiesIndexSourceIDv2Response{}
	statusCode, err := fc.Client.DoReq(flareGetEventActivitiesByIDURL, "GET", data, headers, nil, nil)
	if err != nil {
		return nil, utils.LogError(err)
	}
	if statusCode != 200 {
		return nil, fmt.Errorf("error retrieving flare event activities by ID, received non 200 HTTP response status code: %d", statusCode)
	}

	return data, nil
}

// FlareStealerLogZipFileDownloadResponse ...
type FlareStealerLogZipFileDownloadResponse struct {
	StealerLog struct {
		ExternalURL string `json:"external_url,omitempty"`
	} `json:"stealer_log,omitempty"`
}

// FlareDownloadStealerLogZipFilesThatContainPasswords ...
func (fc *FlareClient) FlareDownloadStealerLogZipFilesThatContainPasswords(data *FlareFireworkActivitiesIndexSourceIDv2Response, outputDir string) ([]string, error) {
	filesToDownload := map[string]struct{}{
		"All Passwords.txt": {},
		"Passwords.txt":     {},
		"passwords.txt":     {},
	}
	downloadedFilePaths := make([]string, 0)
	for _, stealerLogsFile := range data.Activity.Data.Files {
		if _, exists := filesToDownload[stealerLogsFile]; exists {
			flareGetEventActivitiesByIDURL := fmt.Sprintf("%s/firework/v2/activities/%s/download", flareAPIBaseURL, data.Activity.Data.UID)
			headers := map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", fc.Token),
				"Accept":        "text/plain; charset=utf-8",
				"User-Agent":    fc.DefaultUserAgent,
			}
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
			headers := map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", fc.Token),
				"Accept":        "text/plain; charset=utf-8",
				"User-Agent":    fc.DefaultUserAgent,
			}
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

// FlareDownloadStealerLogCookieFiles ... ToDo: Unused
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
		headers := map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", fc.Token),
			"Accept":        "text/plain; charset=utf-8",
			"User-Agent":    fc.DefaultUserAgent,
		}
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

// downloadZip downloads a ZIP file from the provided URL and saves it to the specified output path.
func downloadZip(url, outputPath, userAgent string) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Mimic curl behavior
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download file, status code: %d", resp.StatusCode)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create progress bar
	bar := progressbar.DefaultBytes(
		resp.ContentLength,
		"downloading",
	)

	// Stream the response body directly to the file with progress bar
	_, err = io.Copy(io.MultiWriter(outFile, bar), resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	return nil
}

// FindHighValueCookies ...
func FindHighValueCookies(cookies []Cookie) []Cookie {
	// Define a map to group cookies by their respective providers
	cookieMap := map[string][]string{
		"Microsoft": {
			"ESTSAUTH",                    // Contains user's session information for SSO (transient).
			"ESTSAUTHPERSISTENT",          // Persistent session token for SSO across Microsoft services.
			"ESTSAUTHLIGHT",               // Stores session GUID information, often used in lightweight authentication flows.
			"ESTSAUTHPERSISTENTLIGHT",     // A lightweight version of ESTSAUTHPERSISTENT, often used in hybrid authentication scenarios.
			"x-ms-refreshtokencredential", // Used when Primary Refresh Token (PRT) is active to maintain session state.
			"SSOCOOKIE",                   // Secure authentication cookie enabling seamless SSO across Microsoft services.
			"MSCC",                        // Microsoft account consent cookie, storing user preferences for authentication prompts.
			"MUID",                        // Machine-unique identifier used for tracking authentication and security checks.
			"MSPAuth",                     // Authentication token for Microsoft Account services, used in login sessions.
			"MSPProf",                     // Stores user profile-related authentication data.
			"MSPOK",                       // Helps confirm successful authentication for Microsoft services.
			"RPSAuth",                     // Main authentication token for maintaining session state.
			"RPSSecAuth",                  // Secure authentication token for Microsoft Entra ID and 365 services.
			"MS0",                         // Session management cookie used for authentication and maintaining login state.
			"MSFPC",                       // Used for tracking and authentication across Microsoft services.
			"MSAAuth",                     // Authentication token for Microsoft Account sign-ins.
			"MSAAUTHP",                    // Persistent authentication cookie for Microsoft 365 services.
			"WT_FPC",                      // First-party authentication tracking cookie used for session persistence.
			"MSAToken",                    // Stores a user's token for authentication and access control.
			"FPC",                         // Microsoft’s first-party cookie used for authentication and tracking logged-in sessions.
			"PPAuth",                      // Microsoft Passport authentication token for secure sign-ins.
		},
		"Azure": {
			"x-ms-cpim-trans", // Used for tracking authentication requests and current transactions.
			"x-ms-cpim-sso",   // {Id}: Used for maintaining the SSO session.
			"x-ms-cpim-cache", // {id}_n: Used for maintaining the request state.
			"x-ms-cpim-rp",    // Stores relying party information in federated authentication scenarios.
			"x-ms-cpim-rc",    // Stores the user's authentication state across multiple requests.
			"AzureADAuth",     // Authentication token used specifically in Microsoft Entra ID (Azure AD).
		},
		"Microsoft 365": {
			"OfficeAuth",       // Authentication token for Microsoft 365 applications like Outlook and Teams.
			"AdminConsoleAuth", // Authentication token used for Microsoft Admin Console and Azure Portal access.
		},
		"Microsoft Admin Console": {
			"IDCAuth", // Identity authentication cookie used in Microsoft Admin portals.
			"CtxAuth", // Contextual authentication token for Microsoft Admin and Entra ID portals.
		},
		"SharePoint": {
			"FedAuth", // FedAuth: Used for each top-level site in SharePoint
			"rtFA",    //		rtFA: Used across all of SharePoint for silent authentication
		},
		"Google": {
			"SID",               // Primary session ID cookie, used for authentication and security, lasts for 2 years.
			"HSID",              // Secure cookie containing encrypted user account information, helps prevent fraudulent logins.
			"SSID",              // Used for authentication, security, and session management across Google services.
			"APISID",            // Stores user authentication data for persistent login across Google services.
			"SAPISID",           // Similar to APISID, used for authentication and enforcing security policies.
			"SIDCC",             // Security cookie protecting against unauthorized access and account hijacking.
			"NID",               // Stores user preferences and login-related information, often used in Google search.
			"G_AUTHUSER_H",      // Identifies the signed-in user when multiple accounts are used.
			"GAPS",              // Session management cookie used for login authentication.
			"__Secure-1PSID",    // First-party session ID for authentication and security within Google services.
			"__Secure-3PSID",    // Third-party session ID for authentication across Google's services and third-party sites.
			"__Secure-1PAPISID", // First-party authentication token used for persistent login and security.
			"__Secure-3PAPISID", // Third-party authentication token for maintaining authentication across Google services.
			"__Secure-YEC",      // Security-related cookie, used to enhance authentication and session integrity.
		},
	}

	// fmt.Println("Cookie Map:", cookieMap)
	var highValueCookies []Cookie
	for _, cookie := range cookies {
		for provider, prefixes := range cookieMap {
			for _, prefix := range prefixes {
				if strings.HasPrefix(cookie.Name, prefix) {
					// if verbose print. TODO: include opts.Verbose
					utils.InfoLabelWithColorf("Live Cookie", "yellow", "Cookie %s matches prefix %s for provider: %s", cookie.Name, prefix, provider)
					highValueCookies = append(highValueCookies, cookie)
					break
				}
			}
		}
	}
	utils.InfoLabelWithColorf("Live Cookies", "green", "Found %d live high value cookies", len(highValueCookies))
	return highValueCookies
}

// Cookie ...
type Cookie struct {
	Domain         string
	Secure         bool
	Path           string
	HTTPOnly       bool
	Expiration     int64
	IsExpired      bool
	ExpirationDate string
	Name           string
	Value          string
}

// CookieBro ...
type CookieBro struct {
	Name             string      `json:"name,omitempty"`
	Value            string      `json:"value,omitempty"`
	Domain           string      `json:"domain,omitempty"`
	HostOnly         bool        `json:"hostOnly,omitempty"`
	Path             string      `json:"path,omitempty"`
	Secure           bool        `json:"secure,omitempty"`
	HTTPOnly         bool        `json:"httpOnly,omitempty"`
	SameSite         string      `json:"sameSite,omitempty"`
	Session          bool        `json:"session,omitempty"`
	FirstPartyDomain string      `json:"firstPartyDomain,omitempty"`
	PartitionKey     interface{} `json:"partitionKey,omitempty"`
	ExpirationDate   int         `json:"expirationDate,omitempty"`
	StoreID          string      `json:"storeId,omitempty"`
}

// ParseCookieFile parses a cookies file and returns only the high value live cookies and an error
func ParseCookieFile(filename string) ([]Cookie, []Cookie, error) {
	utils.InfoLabelWithColorf("FLARE STEALER LOGS", "cyan", "Parsing %s for live cookies", filename)
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var cookies []Cookie

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024) // Increase the buffer size to handle large lines
	scanner.Buffer(buf, 1024*1024)  // Set the maximum token size to 1MB

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 7 {
			continue // Skip malformed lines
		}

		secure, err := strconv.ParseBool(strings.ToLower(fields[1])) // ToDo: Double check if this is indeed the secure cookie boolean
		if err != nil {
			continue
		}
		httpOnly, err := strconv.ParseBool(strings.ToLower(fields[3])) // ToDo: Double check if this is indeed the HTTPOnly cookie boolean
		if err != nil {
			continue
		}
		expiration, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			continue
		}

		cookies = append(cookies, Cookie{
			Domain:     fields[0],
			Secure:     secure,
			Path:       fields[2],
			HTTPOnly:   httpOnly,
			Expiration: expiration,
			Name:       fields[5],
			Value:      fields[6],
		})
	}

	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}

	liveCookies, err := CheckCookieExpiration(cookies)
	if err != nil {
		return nil, nil, utils.LogError(err)
	}

	// check live cookies for high value targets
	highValueCookies := FindHighValueCookies(liveCookies)

	return liveCookies, highValueCookies, nil
}

// MapCookiesToCookieBro ...
func MapCookiesToCookieBro(cookies []Cookie) []CookieBro {
	cookieBros := make([]CookieBro, 0)
	for _, cookie := range cookies {
		cookieBros = append(cookieBros, CookieBro{
			Name:           cookie.Name,
			Value:          cookie.Value,
			Domain:         cookie.Domain,
			Path:           cookie.Path,
			Secure:         cookie.Secure,
			HTTPOnly:       cookie.HTTPOnly,
			ExpirationDate: int(cookie.Expiration),
		})
	}

	return cookieBros
}

// CheckCookieExpiration ...
func CheckCookieExpiration(cookies []Cookie) ([]Cookie, error) {
	liveCookies := make([]Cookie, 0)
	for _, cookie := range cookies {
		isExpired, _ := CheckExpirationRFC3339(cookie.Expiration)
		if !isExpired {
			// utils.InfoLabelWithColorf("Cookie", "green", "Cookie %s is not expired until %s", cookie.Name, expirationDate)
			liveCookies = append(liveCookies, cookie)
		}
	}
	return liveCookies, nil
}

// FlareStealerLogsCredential holds the parsed information for each entry
type FlareStealerLogsCredential struct {
	Software string
	URL      string
	Username string
	Password string
}

// UniqueCredentials ...
func UniqueCredentials(credentials []FlareStealerLogsCredential) []FlareStealerLogsCredential {
	uniqueMap := make(map[FlareStealerLogsCredential]struct{})
	var uniqueList []FlareStealerLogsCredential

	for _, cred := range credentials {
		if _, exists := uniqueMap[cred]; !exists {
			uniqueMap[cred] = struct{}{}
			uniqueList = append(uniqueList, cred)
		}
	}

	// Optional: Sort by a field, e.g., Software
	sort.Slice(uniqueList, func(i, j int) bool {
		return uniqueList[i].Software < uniqueList[j].Software
	})

	return uniqueList
}

// parseCredentialsFile parses the file and returns credentials matching the specified domain
func parseCredentialsFile(filename, domain string, userIDFormats []string) ([]FlareStealerLogsCredential, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var credentials []FlareStealerLogsCredential
	scanner := bufio.NewScanner(file)
	var current FlareStealerLogsCredential

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			// Empty line indicates the end of a credential block
			if isCredentialValid(current) {
				credentials = append(credentials, current)
				current = FlareStealerLogsCredential{}
			}
			continue
		}

		// Parse key-value pairs
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "SOFT":
			current.Software = value
		case "URL":
			current.URL = value
		case "USER":
			current.Username = value
		case "PASS":
			current.Password = value
		}
	}

	// Add the last credential if the file doesn't end with an empty line
	if isCredentialValid(current) {
		credentials = append(credentials, current)
	}

	if err = scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Filter credentials based on the domain
	inScopeCredentials := filterInScopeCredentials(credentials, domain, userIDFormats)
	return inScopeCredentials, nil
}

// isCredentialValid checks if a credential has at least a URL or Username
func isCredentialValid(cred FlareStealerLogsCredential) bool {
	return cred.URL != "" || cred.Username != ""
}

// filterInScopeCredentials ensures proper domain matching
func filterInScopeCredentials(credentials []FlareStealerLogsCredential, domain string, userIDFormats []string) []FlareStealerLogsCredential {
	var filtered []FlareStealerLogsCredential
	for _, cred := range credentials {
		for _, userIDFormat := range userIDFormats {
			// this checks if the URL matches the domain or if the username matches the email domain or if the username has the domain prefix without tld or if the username matches the optionally provided userID format that is dynamically converted to an appropriate matching regex
			if isDomainMatch(cred.URL, domain) || isUsernameEmailDomainMatch(cred.Username, domain) || utils.HasBaseDomainWithoutTLDPrefix(cred.Username, domain) || utils.IsUserIDFormatMatch(cred.Username, userIDFormat) {
				filtered = append(filtered, cred)
			}
		}
	}
	return filtered
}

// isDomainMatch strictly matches the domain
func isDomainMatch(credentialURL, domain string) bool {
	parsedURL, err := url.Parse(credentialURL)
	if err != nil {
		return false
	}
	host := parsedURL.Hostname()
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// isUsernameEmailDomainMatch ...
func isUsernameEmailDomainMatch(credentialUsername, domain string) bool {
	emailPattern := fmt.Sprintf("@%s", domain)
	return strings.Contains(credentialUsername, emailPattern)
}

// FlareEventsGlobalSearchByDomain
// Events Queries
// Infostealers by URL:
// metadata.source:stealer_logs* AND features.urls:*.domain.com AND COMPANY-NAME
// metadata.source:stealer_logs* AND features.emails:*@domain.com AND features.urls:*.domain.com
// metadata.source:stealer_logs* AND features.emails:*@domain.com AND features.urls:*.domain.*
//
// Infostealers by Email Domain:
// metadata.source:stealer_logs* AND features.emails:*@example.com
//
// GitHub search
// commit.committer_email:*@domain.comm OR commit.author_email:*@domain.comm
//
// Cookies Search
// metadata.source:stealer_logs* AND cookies.host_key:.domain.com
//
// By default, this function uses the query: "metadata.source:stealer_logs* AND features.emails:*@domain.com"
// Could also check for URLs but this will return customer login data also which is likely out-of-scope, for example:
// metadata.source:stealer_logs* AND (features.emails:*@domain.com OR features.urls:*.domain.com)
// Docs: https://api.docs.flare.io/api-reference/v4/endpoints/global-search
// Query Docs: https://docs.flare.io/queries
func (fc *FlareClient) FlareEventsGlobalSearchByDomain(domain, outputDir, query string, years int) (*FlareEventsGlobalSearchResults, error) {
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
	filterTypes := []string{
		"illicit_networks", "open_web", "leak", "domain", "listing", "forum_content",
		"blog_content", "blog_post", "profile", "chat_message", "ransomleak",
		"infected_devices", "financial_data", "bot", "stealer_log", "paste",
		"social_media", "source_code", "source_code_files", "stack_exchange",
		"google", "service", "buckets", "bucket", "bucket_object",
	} // https://api.docs.flare.io/api-reference/v4/endpoints/global-search#param-type
	filterSeverities := []string{"critical", "high", "medium"}
	postBody := &FlareEventsGlobalSearchBodyParams{
		Query: Query{
			Type:        "query_string",
			QueryString: queryString,
		},
		Size: size,
		Filters: Filters{
			Severity: filterSeverities,
			Type:     filterTypes,
			EstimatedCreatedAt: EstimatedCreatedAt{
				Gte: GetPastISO8601Date(years), // get results no more than 2 years old...
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
	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", fc.Token),
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

// FlareSearchCookiesByDomain ...
// Docs: https://api.docs.flare.io/api-reference/leaksdb/endpoints/post-cookies-search
func (fc *FlareClient) FlareSearchCookiesByDomain(domain, outputDir string) (*FlareSearchCookiesResponse, error) {
	flareSearchCookiesURL := fmt.Sprintf("%s/leaksdb/v2/cookies/_search", flareAPIBaseURL)
	headers := fc.defaultHeaders()
	allData := &FlareSearchCookiesResponse{}
	size := 500
	// current date for ExpiresAfter param
	expiresAfter := time.Now().Format(time.RFC3339)
	names := []string{
		"ESTSAUTH",
		"ESTSAUTHPERSISTENT",
		"ESTSAUTHLIGHT",
		"x-ms-refreshtokencredential",
		"x-ms-cpim-sso",
		"rtFA",
		"session",
		"access_token",
		"refresh_token",
		"token",
	} // TODO: make names an optional CLI arg option
	paths := []string{
		"/",
	} // TODO: make paths an optional CLI arg option
	postBody := &FlareSearchCookiesBodyParams{
		Domain: domain,
		Size:   size,
		Names:  names, // TODO: make names an optional CLI arg option
		Paths:  paths, // TODO: make paths an optional CLI arg option
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

// FlareSearchCredentialsBodyParams ...
type FlareSearchCredentialsBodyParams struct {
	Size  string           `json:"size,omitempty"`
	From  string           `json:"from,omitempty"`
	Query FlareDomainQuery `json:"query"`
}

// FlareDomainQuery ...
type FlareDomainQuery struct {
	Type string `json:"type"`
	Fqdn string `json:"fqdn"`
}

// FlareLeakedCredentialsByDomain
// Docs: https://api.docs.flare.io/api-reference/leaksdb/endpoints/post-credentials-search
func (fc *FlareClient) FlareLeakedCredentialsByDomain(domain, outputDir string) (*FlareSearchCredentials, error) {
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

	if err := parseFlareDataWriteToOutputFiles(domain, outputDir, allData); err != nil {
		return nil, utils.LogError(err)
	}

	return allData, nil
}

// parseFlareDataWriteToOutputFiles writes flare results to txt files
func parseFlareDataWriteToOutputFiles(domain, outputDir string, allData *FlareSearchCredentials) error {
	uniqueEmailsCount := len(allData.Items)
	var allEmails []string
	var userPass []string
	var pitchforkUsers []string
	var pitchforkPasswords []string
	// Use a map to keep track of unique user:pass pairs
	uniqueUserPass := make(map[string]bool)
	for _, i := range allData.Items {
		allEmails = append(allEmails, i.IdentityName)
		if i.Hash != "" && !utils.ContainsExactMatch([]string{"None", "none", "Null", nullString, "nil", "<nil>", " "}, i.Hash) {
			userPassKey := fmt.Sprintf("%s:%s", i.IdentityName, i.Hash)
			// Check if this pair has already been added
			if !uniqueUserPass[userPassKey] {
				userPass = append(userPass, userPassKey)
				pitchforkUsers = append(pitchforkUsers, i.IdentityName)
				pitchforkPasswords = append(pitchforkPasswords, i.Hash)

				// Mark this pair as added
				uniqueUserPass[userPassKey] = true
			}
		}
	}
	uniqueEmails := utils.SortUnique(allEmails)
	utils.InfoLabelWithColorf("FLARE LEAK DATA", "green", "Found %d unique emails for %s", uniqueEmailsCount, domain)
	if err := utils.WriteLines(uniqueEmails, fmt.Sprintf("%s/flare-unique-emails-%s.txt", outputDir, domain)); err != nil {
		return utils.LogError(err)
	}
	utils.InfoLabelWithColorf("FLARE LEAK DATA", "green", "Found %d unique credential pairs for %s", len(userPass), domain)
	if err := utils.WriteLines(userPass, fmt.Sprintf("%s/flare-unique-creds-%s.txt", outputDir, domain)); err != nil {
		return utils.LogError(err)
	}
	if err := utils.WriteLines(pitchforkUsers, fmt.Sprintf("%s/flare-pitchfork-users-%s.txt", outputDir, domain)); err != nil {
		return utils.LogError(err)
	}
	if err := utils.WriteLines(pitchforkPasswords, fmt.Sprintf("%s/flare-pitchfork-passwords-%s.txt", outputDir, domain)); err != nil {
		return utils.LogError(err)
	}
	return nil
}

// FlareCredentialPairs ...
type FlareCredentialPairs struct {
	Email      string
	Password   string
	Hash       string
	SourceID   string
	Domain     string
	ImportedAt time.Time
	LeakedAt   interface{}
	BreachedAt interface{}
}

// FlareCreds ...
type FlareCreds struct {
	Data []FlareCredentialPairs
}

// mapBulkEmailCredsToCSVFormat ...
func mapBulkEmailCredsToCSVFormat(matchedEmailCredResults *FlareListByBulkAccountResponse) (*FlareCreds, error) {
	flareCreds := &FlareCreds{}
	for email, emailResults := range *matchedEmailCredResults {
		if len(emailResults.Passwords) > 0 {
			for _, password := range emailResults.Passwords {
				cred := FlareCredentialPairs{
					Email: email,
				}
				switch {
				case isHash(password.Hash):
					cred.Hash = password.Hash
				case isLikelyAnEncryptedValue(password.Hash):
					cred.Hash = password.Hash
				default:
					if !utils.ContainsExactMatch([]string{"None", "none", "Null", nullString, ",null", "(null)", "nil", "<nil>", "", " "}, password.Hash) {
						cred.Password = password.Hash
						cred.Hash = password.CredentialHash
					}
				}
				// fill out remaining values to cred
				importedAt, err := time.Parse(time.RFC3339, password.ImportedAt)
				if err != nil {
					return nil, fmt.Errorf("failed to parse ImportedAt for email %s: %w", email, err)
				}
				cred.ImportedAt = importedAt
				cred.SourceID = password.SourceID
				breachedAt, err := time.Parse(time.RFC3339, password.Source.BreachedAt)
				if err != nil {
					return nil, fmt.Errorf("failed to parse BreachedAt for email %s: %w", email, err)
				}
				cred.BreachedAt = breachedAt
				leakedAt, err := time.Parse(time.RFC3339, password.Source.LeakedAt)
				if err != nil {
					return nil, fmt.Errorf("failed to parse LeakedAt for email %s: %w", email, err)
				}
				cred.LeakedAt = leakedAt
				cred.Domain = *password.Domain

				flareCreds.Data = append(flareCreds.Data, cred)
			}
		}
	}
	return flareCreds, nil
}

// setFlareCredentialPairsStructFromFlareData ...
func setFlareCredentialPairsStructFromFlareData(data *FlareSearchCredentials) *FlareCreds {
	flareCreds := &FlareCreds{}
	for _, v := range data.Items {
		flareData := FlareCredentialPairs{}
		flareData.Email = v.IdentityName
		// check if the v.Hash value is a password or a hash...
		// this is a funky work around because Flare currently does not differentiate between hashes, passwords, or encrypted values...
		// this catches most likely non cleartext passwords. some URLs come through but who knows whatsagoinon'....
		// ToDo: Feature request differentiation to Flare peeps...
		switch {
		case isHash(v.Hash):
			flareData.Hash = v.Hash
		case isLikelyAnEncryptedValue(v.Hash):
			flareData.Hash = v.Hash
		default:
			if !utils.ContainsExactMatch([]string{"None", "none", "Null", nullString, ",null", "(null)", "nil", "<nil>", "", " "}, v.Hash) {
				flareData.Password = v.Hash
			}
		}
		flareData.Domain = v.Domain
		flareData.SourceID = v.SourceID
		flareData.ImportedAt = v.ImportedAt
		if leakedAt, ok := v.Source.LeakedAt.(time.Time); ok {
			flareData.LeakedAt = leakedAt
		}
		if leakedAt, ok := v.Source.LeakedAt.(string); ok {
			parsedTime, err := time.Parse(time.RFC3339, leakedAt)
			if err != nil {
				flareData.LeakedAt = leakedAt
			}
			flareData.LeakedAt = parsedTime
		}
		if breachedAt, ok := v.Source.BreachedAt.(time.Time); ok {
			flareData.BreachedAt = breachedAt
		}
		if breachedAt, ok := v.Source.LeakedAt.(string); ok {
			parsedTime, err := time.Parse(time.RFC3339, breachedAt)
			if err != nil {
				flareData.BreachedAt = breachedAt
			}
			flareData.BreachedAt = parsedTime
		}
		// append data here in case there are multiple passwords for the same Name
		flareCreds.Data = append(flareCreds.Data, flareData)
	}
	return flareCreds
}

// isLikelyAnEncryptedValue ...
func isLikelyAnEncryptedValue(input string) bool {
	// Normalize input by trimming whitespace and converting to lowercase
	input = strings.TrimSpace(strings.ToLower(input))
	if strings.HasSuffix(input, "=") && valid.IsBase64(input) {
		// likely an encrypted value that flare includes in the Items[n].Hash key...
		return true
	}

	return false
}

// isHash checks if the input string matches the format of common hash algorithm formats.
// hopefully a temporary work-around since flare does not distinguish by credential type and groups hashes and cleartext passwords into the same hash key.
// this is to reduce non cleartext password results noise that can muddy up the cred stuffing auto generated lists...
func isHash(input string) bool {
	// Normalize input by trimming whitespace and converting to lowercase
	input = strings.TrimSpace(strings.ToLower(input))

	// Define regex patterns for hash formats
	hashPatterns := map[string]string{
		"MD5":       "^[a-f0-9]{32}$",
		"SHA-1":     "^[a-f0-9]{40}$",
		"TIGER-192": "^[a-f0-9]{48}$",
		"SHA-3-224": "^[a-f0-9]{56}$",
		"SHA-256":   "^[a-f0-9]{64}$",
		"SHA-384":   "^[a-f0-9]{96}$",
		"SHA-512":   "^[a-f0-9]{128}$",
		"Blowfish":  `^\$2[aby]?\$\d{1,2}\$[./a-zA-Z0-9]{53}$`, // Blowfish ($2a$, $2b$, $2y$)
	}

	// Check the input against each pattern
	for _, pattern := range hashPatterns {
		match, _ := regexp.MatchString(pattern, input)
		if match {
			return true
		}
	}

	// additional checks for sampled hash values
	if utils.ContainsPrefix([]string{"pbkdf2_sha256", "pbkdf2_sha512", "c2NyeXB0AA4AAAAIAAAA", "$S$D", "$P$B", "sha1$2", "sha1$4"}, input) && len(input) >= 32 {
		return true
	}

	return false
}

// SearchEmailsInBulk ...
func SearchEmailsInBulk(opts *Options, emails []string) error {
	flareOutputDir := fmt.Sprintf("%s/breach_data", opts.Output)
	if err := os.MkdirAll(flareOutputDir, 0750); err != nil {
		return utils.LogError(err)
	}
	// new flare client
	fc, err := NewFlareClient(opts.APIKeys.APIKeys.FlareAPI, opts.APIKeys.APIKeys.FlareTenantID)
	if err != nil {
		return utils.LogError(err)
	}

	utils.InfoLabelWithColorf("FLARE", "cyan", "Searching for emails in bulk...")
	matchedEmailCredResults, err := fc.FlareBulkCredentialLookup(emails, flareOutputDir)
	if err != nil {
		return utils.LogError(err)
	}
	// parse passwords from results
	flareCreds, err := mapBulkEmailCredsToCSVFormat(matchedEmailCredResults)
	if err != nil {
		return utils.LogError(err)
	}
	// write to CSV file
	csvOutputFile := fmt.Sprintf("%s/flare-bulk-credential-lookup.csv", flareOutputDir)
	if err = utils.WriteStructToCSVFile(flareCreds.Data, csvOutputFile); err != nil {
		return utils.LogError(err)
	}
	// generate xlsx file from csv file
	if err = utils.CSVsToExcel([]string{csvOutputFile}, flareOutputDir); err != nil {
		return utils.LogError(err)
	}

	return nil
}

// SearchFlareLeaksDatabase ...
func SearchFlareLeaksDatabase(opts *Options, domains []string) (*FlareCreds, error) {
	flareOutputDir := fmt.Sprintf("%s/breach_data", opts.Output)
	if err := os.MkdirAll(flareOutputDir, 0750); err != nil {
		return nil, utils.LogError(err)
	}
	// new flare client
	fc, err := NewFlareClient(opts.APIKeys.APIKeys.FlareAPI, opts.APIKeys.APIKeys.FlareTenantID)
	if err != nil {
		return nil, utils.LogError(err)
	}

	flareData := &FlareCreds{}
	var flareCSVFiles []string
	for _, domain := range domains {
		outputJSON := fmt.Sprintf("%s/flare-leaks-%s.json", flareOutputDir, domain)
		outputCSV := fmt.Sprintf("%s/flare-leaks-%s.csv", flareOutputDir, domain)
		utils.InfoLabelWithColorf("FLARE LEAK DATA", "blue", "Checking Flare Leaked Credentials API for %s", domain)
		data, err := fc.FlareLeakedCredentialsByDomain(domain, flareOutputDir)
		if err != nil {
			utils.LogWarningf("something went wrong retrieving flare leak data for %s, Error: %s", domain, err.Error())
			continue
		}

		// write complete full raw data for domain to its own JSON file
		if err = utils.WriteStructToJSONFile(data, outputJSON); err != nil {
			return nil, utils.LogError(err)
		}
		// parse through data and extract just the username/email , password, and leak source, and write to CSV file
		flareCSVData := setFlareCredentialPairsStructFromFlareData(data)
		flareData.Data = append(flareData.Data, flareCSVData.Data...)
		// write to CSV file
		if err = utils.WriteStructToCSVFile(flareCSVData.Data, outputCSV); err != nil {
			return nil, utils.LogError(err)
		}
		if err = dumpDicerNG(domain, flareOutputDir, flareCSVData.Data); err != nil {
			return nil, utils.LogError(err)
		}
		flareCSVFiles = append(flareCSVFiles, outputCSV)
	}

	if err = utils.CSVsToExcel(flareCSVFiles, fmt.Sprintf("%s/flare-breach-data-results.xlsx", flareOutputDir)); err != nil {
		utils.LogWarningf("failed to generate xlsx report from csv files: %s %+v", strings.Join(flareCSVFiles, "\n"), err)
	}

	return flareData, nil
}

// dumpDicerNG groups credentials into waves and writes them into separate files
func dumpDicerNG(domain, flareOutputDir string, creds []FlareCredentialPairs) error {
	credStuffingDir := fmt.Sprintf("%s/credential_stuffing", flareOutputDir)

	// Create the output directory if it doesn't exist
	if err := os.MkdirAll(credStuffingDir, 0750); err != nil {
		return utils.LogError(err)
	}

	// Map to store unique credential pairs for each email
	emailMap := make(map[string]map[string]bool)

	// Group unique credential pairs by email
	for _, cred := range creds {
		if cred.Password == "" { // Skip if password is empty
			continue
		}
		if _, exists := emailMap[cred.Email]; !exists {
			emailMap[cred.Email] = make(map[string]bool)
		}
		emailMap[cred.Email][cred.Password] = true
	}

	// Create waves based on the number of unique passwords per email
	waves := make(map[int][]string)
	for email, passwords := range emailMap {
		passwordList := getSortedKeys(passwords)
		for i, password := range passwordList {
			entry := fmt.Sprintf("%s:%s", email, password)
			waves[i] = append(waves[i], entry)
		}
	}

	// Write each wave's unique credentials into a separate file
	utils.InfoLabelWithColorf("FLARE LEAK DATA", "cyan", "Generating cleartext credential stuffing files excluding common hashes and likely encrypted values")
	for waveIndex, entries := range waves {
		waveNumber := waveIndex + 1
		credStuffingFilePath := fmt.Sprintf("%s/wave-%s-%d.txt", credStuffingDir, domain, waveNumber)

		// Sort the entries for consistency
		sort.Strings(entries)

		// Write the entries to the file
		utils.InfoLabelWithColorf("FLARE LEAK DATA", "magenta", "Writing %d unique credential stuffing pairs to: %s", len(entries), credStuffingFilePath)
		if err := utils.WriteLines(entries, credStuffingFilePath); err != nil {
			return utils.LogError(err)
		}
	}

	return nil
}

// Helper function to get sorted keys from a map
func getSortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// GetPastISO8601Date returns the ISO-8601 (RFC3339) timestamp X years prior to now
func GetPastISO8601Date(yearsAgo int) string {
	// Get the current UTC time
	now := time.Now().UTC()

	// Subtract 4 years from the current date
	pastTime := now.AddDate(-yearsAgo, 0, 0)

	// Format the past date in ISO-8601 (RFC3339 format)
	return pastTime.Format(time.RFC3339)
}

// CheckExpiration checks if a given epoch timestamp is expired and returns:
// - A bool indicating whether it's expired
// - A time.Duration representing time until expiration or time since expiration
func CheckExpiration(epochTimestamp int64) (bool, time.Duration) {
	expirationTime := time.Unix(epochTimestamp, 0)
	now := time.Now()
	duration := expirationTime.Sub(now)

	expired := duration < 0
	return expired, duration
}

// CheckExpirationRFC3339 checks if a given epoch timestamp is expired and returns:
// - A bool indicating whether it's expired
// - A string representing the expiration time in RFC3339 format
func CheckExpirationRFC3339(epochTimestamp int64) (bool, string) {
	expirationTime := time.Unix(epochTimestamp, 0).UTC()
	expired := time.Now().After(expirationTime)
	return expired, expirationTime.Format(time.RFC3339)
}
