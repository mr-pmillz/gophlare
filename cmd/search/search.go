package search

import (
	"bufio"
	"fmt"
	valid "github.com/asaskevich/govalidator"
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/mr-pmillz/gophlare/utils"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

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

// DownloadAllStealerLogPasswordFiles retrieves and processes stealer log password files for specified domains in the given scope.
// It initializes necessary directories, queries Flare API for events, downloads relevant zip files, extracts credentials,
// and compiles the results into CSV and Excel files. Logs errors and status updates throughout its execution.
// Returns an error if any operation fails during the entire process.
func DownloadAllStealerLogPasswordFiles(opts *phlare.Options, scope *phlare.Scope) error {
	flareOutputDir := fmt.Sprintf("%s/breach_data/stealer_logs", opts.Output)
	if err := os.MkdirAll(flareOutputDir, 0750); err != nil {
		return utils.LogError(err)
	}

	fc, err := phlare.NewFlareClient(opts.APIKeys.APIKeys.FlareAPI, opts.UserAgent, opts.APIKeys.APIKeys.FlareTenantID, opts.Timeout)
	if err != nil {
		return utils.LogError(err)
	}

	allCSVFiles := make([]string, 0)
	for _, domain := range scope.Domains {
		utils.InfoLabelWithColorf("FLARE", "cyan", "Checking Stealer Logs for %s", domain)

		results, err := phlare.QueryGlobalEvents(fc, domain, flareOutputDir, opts.Query, opts.From, opts.To, scope.Severity, scope.EventsFilterTypes)
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

	if err = exportCSVToExcel(allCSVFiles, flareOutputDir); err != nil {
		return err
	}

	utils.InfoLabelWithColorf("FLARE", "blue", "Finished downloading all stealer log zip files from Flare that contain passwords")
	return nil
}

// downloadZipFilesAndProcessPasswordResults downloads ZIP files containing stealer logs, parses passwords, and processes results.
// It takes the search results, a FlareClient instance, a download limit, output directory, domain, user ID formats, and a keepZips flag.
// Returns []FlareStealerLogsCredential a unique list of extracted credentials and any errors encountered during the process.
func downloadZipFilesAndProcessPasswordResults(results *phlare.FlareEventsGlobalSearchResults, fc *phlare.FlareClient, limit int, outputDir, domain string, userIDFormats []string, keepZips bool) ([]phlare.FlareStealerLogsCredential, error) {
	allDownloadedFiles, allFlareStealerLogCredentials := make([]string, 0), make([]phlare.FlareStealerLogsCredential, 0)
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

// parseDownloadedFilesForPasswordsAndCookies parses downloaded files to extract passwords and cookies specific to a domain.
// It extracts credential information, live cookies, and high-value cookies from specified files.
// Parameters:
// - files: A list of file paths to analyze and parse.
// - userIDFormats: Formats used to identify user IDs within the credentials.
// - domain: The domain to which the credentials and cookies should be scoped.
// Returns:
// - A slice of parsed credentials (FlareStealerLogsCredential), live cookie data (CookieBro), high-value cookie data (CookieBro).
// - An error if any processing step fails.
func parseDownloadedFilesForPasswordsAndCookies(files, userIDFormats []string, domain string) ([]phlare.FlareStealerLogsCredential, []phlare.CookieBro, []phlare.CookieBro, error) {
	allParsedCredentials := make([]phlare.FlareStealerLogsCredential, 0)
	allCookieBros := make([]phlare.CookieBro, 0)
	allHighValueCookieBros := make([]phlare.CookieBro, 0)
	// by default when downloading the zips, process the password files for the in-scope domain
	filesToParse := map[string]struct{}{
		"All Passwords.txt": {},
		"Passwords.txt":     {},
		"passwords.txt":     {},
	}

	for _, file := range files {
		utils.InfoLabelWithColorf("FLARE", "blue", "Checking stealer log zip file for creds: %s", file)
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

		if err = os.RemoveAll(tempDir); err != nil {
			return nil, nil, nil, utils.LogError(err)
		}
	}
	return allParsedCredentials, allCookieBros, allHighValueCookieBros, nil
}

// parseCredentialsFile parses the file and returns credentials matching the specified domain
func parseCredentialsFile(filename, domain string, userIDFormats []string) ([]phlare.FlareStealerLogsCredential, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var credentials []phlare.FlareStealerLogsCredential
	scanner := bufio.NewScanner(file)
	var current phlare.FlareStealerLogsCredential

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			// Empty line indicates the end of a credential block
			if isCredentialValid(current) {
				credentials = append(credentials, current)
				current = phlare.FlareStealerLogsCredential{}
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
func isCredentialValid(cred phlare.FlareStealerLogsCredential) bool {
	return cred.URL != "" || cred.Username != ""
}

// filterInScopeCredentials ensures proper domain matching
func filterInScopeCredentials(credentials []phlare.FlareStealerLogsCredential, domain string, userIDFormats []string) []phlare.FlareStealerLogsCredential {
	var filtered []phlare.FlareStealerLogsCredential
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

// writeCredentialsToCSV writes credentials to a CSV file
func writeCredentialsToCSV(credentials []phlare.FlareStealerLogsCredential, outputDir, domain string) (string, error) {
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

// FlareLeaksDatabaseSearchByDomain queries a database of leaked credentials for specified domains using the Flare API and saves structured results.
func FlareLeaksDatabaseSearchByDomain(opts *phlare.Options, domains []string) (*FlareCreds, error) {
	flareOutputDir := fmt.Sprintf("%s/breach_data", opts.Output)
	if err := os.MkdirAll(flareOutputDir, 0750); err != nil {
		return nil, utils.LogError(err)
	}
	// new flare client
	fc, err := phlare.NewFlareClient(opts.APIKeys.APIKeys.FlareAPI, opts.UserAgent, opts.APIKeys.APIKeys.FlareTenantID, opts.Timeout)
	if err != nil {
		return nil, utils.LogError(err)
	}

	flareData := &FlareCreds{}
	var flareCSVFiles []string
	for _, domain := range domains {
		outputJSON := fmt.Sprintf("%s/flare-leaks-%s.json", flareOutputDir, domain)
		outputCSV := fmt.Sprintf("%s/flare-leaks-%s.csv", flareOutputDir, domain)
		utils.InfoLabelWithColorf("FLARE LEAK DATA", "blue", "Checking Flare Leaked Credentials API for %s", domain)
		data, err := fc.FlareLeakedCredentialsByDomain(domain)
		if err != nil {
			utils.LogWarningf("something went wrong retrieving flare leak data for %s, Error: %s", domain, err.Error())
			continue
		}
		if err = parseFlareDataWriteToOutputFiles(domain, flareOutputDir, data); err != nil {
			return nil, utils.LogError(err)
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

// UniqueCredentials removes duplicate credentials from the input slice and optionally sorts them by the Software field.
func UniqueCredentials(credentials []phlare.FlareStealerLogsCredential) []phlare.FlareStealerLogsCredential {
	uniqueMap := make(map[phlare.FlareStealerLogsCredential]struct{})
	var uniqueList []phlare.FlareStealerLogsCredential

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

// parseFlareDataWriteToOutputFiles processes FlareSearchCredentials data, extracts unique entries, and writes them to output files.
// Parameters:
//   - domain: The domain to include in log messages and output filenames.
//   - outputDir: The directory where the output files will be written.
//   - allData: Pointer to FlareSearchCredentials containing the data to be processed.
//
// Returns an error if file writing or other processing fails.
func parseFlareDataWriteToOutputFiles(domain, outputDir string, allData *phlare.FlareSearchCredentials) error {
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

const nullString = "null"

// setFlareCredentialPairsStructFromFlareData parses FlareSearchCredentials and maps them to a FlareCreds structure.
func setFlareCredentialPairsStructFromFlareData(data *phlare.FlareSearchCredentials) *FlareCreds {
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

// isLikelyAnEncryptedValue checks if the given input string is likely an encrypted value by evaluating its format.
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

// SearchEmailsInBulk performs a bulk lookup of email credentials using the Flare API and outputs results in CSV and XLSX formats.
// It utilizes the provided options for configuration and accepts a slice of emails to search for breaches.
// Results are saved in a specified output directory within the breach_data folder.
func SearchEmailsInBulk(opts *phlare.Options, emails []string) error {
	flareOutputDir := fmt.Sprintf("%s/breach_data", opts.Output)
	if err := os.MkdirAll(flareOutputDir, 0750); err != nil {
		return utils.LogError(err)
	}
	// new flare client
	fc, err := phlare.NewFlareClient(opts.APIKeys.APIKeys.FlareAPI, opts.UserAgent, opts.APIKeys.APIKeys.FlareTenantID, opts.Timeout)
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
	xlsxOutputFile := fmt.Sprintf("%s/flare-bulk-credential-lookup.xlsx", flareOutputDir)
	if err = utils.CSVsToExcel([]string{csvOutputFile}, xlsxOutputFile); err != nil {
		return utils.LogError(err)
	}

	return nil
}

// mapBulkEmailCredsToCSVFormat converts bulk email credential lookup data into a standardized CSV data format.
// matchedEmailCredResults is the bulk account response containing mapped emails and associated credential data.
// Returns a pointer to FlareCreds, which holds the transformed credential pairs, or an error if parsing fails.
// nolint:gocognit
func mapBulkEmailCredsToCSVFormat(matchedEmailCredResults *phlare.FlareListByBulkAccountResponse) (*FlareCreds, error) {
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
				cred.SourceID = password.SourceID
				if password.ImportedAt != "" {
					importedAt, err := time.Parse(time.RFC3339, password.ImportedAt)
					if err != nil {
						return nil, fmt.Errorf("failed to parse ImportedAt for email %s: %w", email, err)
					}
					cred.ImportedAt = importedAt
				}
				if password.Source.BreachedAt != "" {
					breachedAt, err := time.Parse(time.RFC3339, password.Source.BreachedAt)
					if err != nil {
						return nil, fmt.Errorf("failed to parse BreachedAt for email %s: %w", email, err)
					}
					cred.BreachedAt = breachedAt
				}
				if password.Source.LeakedAt != "" {
					leakedAt, err := time.Parse(time.RFC3339, password.Source.LeakedAt)
					if err != nil {
						return nil, fmt.Errorf("failed to parse LeakedAt for email %s: %w", email, err)
					}
					cred.LeakedAt = leakedAt
				}
				cred.Domain = *password.Domain
				flareCreds.Data = append(flareCreds.Data, cred)
			}
		}
	}
	return flareCreds, nil
}
