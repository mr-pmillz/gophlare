package bloodhound

import (
	"fmt"
	"github.com/mr-pmillz/gophlare/bloodhound"
	"github.com/mr-pmillz/gophlare/utils"
	"os"
	"sort"
	"strings"
	"sync"
)

// ProcessData ...
func ProcessData(opts *bloodhound.Options) error {
	// correlate the data
	correlatedBHUserData, err := CorrelateLeakDataWithBloodHoundData(opts)
	if err != nil {
		return utils.LogError(err)
	}
	if err = WriteCredStuffingFiles(correlatedBHUserData, opts.OutputDir); err != nil {
		return utils.LogError(err)
	}

	if opts.UpdateBloodhound {
		if err = UpdateBloodHoundUserData(opts); err != nil {
			return utils.LogError(err)
		}
	}

	return nil
}

// UpdateBloodHoundUserData ...
func UpdateBloodHoundUserData(opts *bloodhound.Options) error {
	fmt.Println("Updating bloodhound users data...TODO")

	return nil
}

// WriteCredStuffingFiles ...
func WriteCredStuffingFiles(data *bloodhound.BHCEUserData, outputDir string) error {
	lines := make([]string, 0)
	linesNoAtDomain := make([]string, 0)
	for _, user := range data.Data {
		if user.Properties.HasBreachData {
			for _, leak := range user.BreachData {
				if leak.Password == "" {
					continue
				}
				line := fmt.Sprintf("%s:%s", user.Properties.Name, leak.Password)
				lineNoAtDomain := fmt.Sprintf("%s:%s", user.Properties.Samaccountname, leak.Password)
				lines = append(lines, line)
				linesNoAtDomain = append(linesNoAtDomain, lineNoAtDomain)
			}
		}
	}
	userIDCredStuffingOutputTextFile := fmt.Sprintf("%s/userID-cred-stuffing.txt", outputDir)
	userIDNoAtDomainCredStuffingOutputTextFile := fmt.Sprintf("%s/SamAccountName-cred-stuffing.txt", outputDir)
	if err := utils.WriteLines(utils.SortUnique(lines), userIDCredStuffingOutputTextFile); err != nil {
		return utils.LogError(err)
	}
	if err := utils.WriteLines(utils.SortUnique(linesNoAtDomain), userIDNoAtDomainCredStuffingOutputTextFile); err != nil {
		return utils.LogError(err)
	}
	// create credential stuffing wave files
	if err := dumpDicerNG(outputDir, data); err != nil {
		return utils.LogError(err)
	}

	return nil
}

// CorrelateLeakDataWithBloodHoundData processes user data against leak data with optimized performance
func CorrelateLeakDataWithBloodHoundData(opts *bloodhound.Options) (*bloodhound.BHCEUserData, error) {
	// TODO: check goldmine data

	// Parse leak data
	flareLeaksByDomainData, err := bloodhound.ParseFlareLeaksByDomainFile(opts.FlareCredsByDomainJSONFile)
	if err != nil {
		return nil, utils.LogError(err)
	}

	bhUsersData := &bloodhound.BHCEUserData{}
	// check if bloodhound users json file is provided
	if opts.BloodhoundUsersJSONFile != "" {
		bhData, err := bloodhound.ParseBloodHoundUsersFile(opts.BloodhoundUsersJSONFile)
		if err != nil {
			return nil, utils.LogError(err)
		}
		bhUsersData = bhData
	} else {
		// Set up a neo4j database connection
		neo4jOpts := bloodhound.NewNeo4jDBOptions(opts.Neo4jHost, opts.Neo4jPort, opts.Neo4jUser, opts.Neo4jPassword)
		db, err := bloodhound.NewNeo4jDBConnection(neo4jOpts)
		if err != nil {
			return nil, utils.LogError(err)
		}

		// Get user data
		users, err := db.GetAllUserData()
		if err != nil {
			return nil, utils.LogError(err)
		}
		bhUsersData = users
	}

	// Create an optimized map of leak data for O(1) lookups
	leaksByDomainAndIdentity := getLeaksByIdentityMap(flareLeaksByDomainData)

	// Determine whether to use parallel processing based on data size
	const numWorkers = 4
	const thresholdForParallel = 1000 // Arbitrary threshold, adjust based on performance testing

	// Use parallel processing for large datasets
	if len(bhUsersData.Data) > thresholdForParallel {
		BHCEUserWithBreachData, err := processUsersInParallel(bhUsersData.Data, leaksByDomainAndIdentity, numWorkers)
		if err != nil {
			return nil, utils.LogError(err)
		}
		return &bloodhound.BHCEUserData{
			Data: *BHCEUserWithBreachData,
		}, nil
	}

	// For smaller datasets, use the optimized sequential approach
	BHCEUserWithBreachData, err := processUsersSequentially(bhUsersData.Data, leaksByDomainAndIdentity)
	if err != nil {
		return nil, utils.LogError(err)
	}
	return &bloodhound.BHCEUserData{
		Data: *BHCEUserWithBreachData,
	}, nil
}

// getLeaksByIdentityMap ...
func getLeaksByIdentityMap(flareLeaksByDomainData *bloodhound.FlareCreds) map[string]map[string][]bloodhound.LeakInfo {
	// Create an optimized map of leak data for O(1) lookups
	// Map structure: domain -> email -> []LeakInfo{Hash, BreachedAt}
	leaksByDomainAndIdentity := make(map[string]map[string][]bloodhound.LeakInfo)
	for _, leakData := range flareLeaksByDomainData.Data {
		domainKey := strings.ToLower(leakData.Domain)
		identityKey := strings.ToLower(leakData.Email)

		if _, exists := leaksByDomainAndIdentity[domainKey]; !exists {
			leaksByDomainAndIdentity[domainKey] = make(map[string][]bloodhound.LeakInfo)
		}
		leaksByDomainAndIdentity[domainKey][identityKey] = append(
			leaksByDomainAndIdentity[domainKey][identityKey],
			bloodhound.LeakInfo{
				Password:   leakData.Password,
				BreachedAt: leakData.BreachedAt,
			},
		)
	}
	return leaksByDomainAndIdentity
}

// processUsersSequentially processes users in a single thread with map lookups
func processUsersSequentially(users []bloodhound.Data, leaksByDomainAndIdentity map[string]map[string][]bloodhound.LeakInfo) (*[]bloodhound.Data, error) {
	updatedUsersData := make([]bloodhound.Data, 0, len(users))
	for _, user := range users {
		// Skip disabled users early
		if !user.Properties.Enabled {
			continue
		}

		baseADDomain, err := utils.ExtractBaseDomain(user.Properties.Domain)
		if err != nil {
			continue
		}

		domainKey := strings.ToLower(baseADDomain)
		emailKey := strings.ToLower(user.Properties.Email)

		// Check if we have leaks for this domain and email with O(1) lookups
		if leaksByDomain, ok := leaksByDomainAndIdentity[domainKey]; ok {
			for _, leak := range leaksByDomain[emailKey] {
				user.BreachData = append(user.BreachData, bloodhound.LeakInfo{
					Password:   leak.Password,
					BreachedAt: leak.BreachedAt,
				})
				breachHappenedAfterPWLastSetDate, _, err := utils.CompareBreachedAtToPasswordLastSetDate(leak.BreachedAt, user.Properties.Pwdlastset)
				if err != nil {
					return nil, utils.LogError(err)
				}
				if breachHappenedAfterPWLastSetDate {
					user.Properties.HasBreachDataAfterPwdLastSet = true
				}
			}
			if len(user.BreachData) > 0 {
				user.Properties.HasBreachData = true
				updatedUsersData = append(updatedUsersData, user)
			}
		}
	}
	return &updatedUsersData, nil
}

// processUsersInParallel processes users using multiple goroutines for improved performance
//
//nolint:gocognit
func processUsersInParallel(users []bloodhound.Data, leaksByDomainAndIdentity map[string]map[string][]bloodhound.LeakInfo, numWorkers int) (*[]bloodhound.Data, error) {
	updatedUsersData := make([]bloodhound.Data, 0, len(users))
	// Split users into chunks for parallel processing
	userChunks := chunkUsers(users, numWorkers)

	var wg sync.WaitGroup
	resultChan := make(chan bloodhound.Data, len(users)) // Buffer for all possible results

	// Process each chunk in a separate goroutine
	for _, chunk := range userChunks {
		wg.Add(1)
		go func(userChunk []bloodhound.Data) {
			defer wg.Done()
			for _, user := range userChunk {
				// Skip disabled users early
				if !user.Properties.Enabled {
					continue
				}

				baseADDomain, err := utils.ExtractBaseDomain(user.Properties.Domain)
				if err != nil {
					continue
				}

				domainKey := strings.ToLower(baseADDomain)
				emailKey := strings.ToLower(user.Properties.Email)

				// Check if we have leaks for this domain and email with O(1) lookups
				if leaksByDomain, ok := leaksByDomainAndIdentity[domainKey]; ok {
					for _, leak := range leaksByDomain[emailKey] {
						user.BreachData = append(user.BreachData, bloodhound.LeakInfo{
							Password:   leak.Password,
							BreachedAt: leak.BreachedAt,
						})
						breachHappenedAfterPWLastSetDate, _, err := utils.CompareBreachedAtToPasswordLastSetDate(leak.BreachedAt, user.Properties.Pwdlastset)
						if err != nil {
							continue
						}
						if breachHappenedAfterPWLastSetDate {
							user.Properties.HasBreachDataAfterPwdLastSet = true
						}
					}
					if len(user.BreachData) > 0 {
						user.Properties.HasBreachData = true
						resultChan <- user
					}
				}
			}
		}(chunk)
	}

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Print results as they come in
	for result := range resultChan {
		updatedUsersData = append(updatedUsersData, result)
	}

	return &updatedUsersData, nil
}

// chunkUsers splits users into approximately equal chunks for parallel processing
func chunkUsers(users []bloodhound.Data, numChunks int) [][]bloodhound.Data {
	if numChunks <= 0 {
		return [][]bloodhound.Data{users}
	}

	// Adjust numChunks if we have fewer users than requested chunks
	if len(users) < numChunks {
		numChunks = len(users)
	}

	// Calculate chunk size
	chunkSize := (len(users) + numChunks - 1) / numChunks // Ceiling division

	chunks := make([][]bloodhound.Data, 0, numChunks)
	for i := 0; i < len(users); i += chunkSize {
		end := i + chunkSize
		if end > len(users) {
			end = len(users)
		}
		chunks = append(chunks, users[i:end])
	}

	return chunks
}

// dumpDicerNG groups credentials into waves and writes them into separate files
//
//nolint:gocognit
func dumpDicerNG(flareOutputDir string, data *bloodhound.BHCEUserData) error {
	credStuffingDir := fmt.Sprintf("%s/credential_stuffing", flareOutputDir)
	credStuffingDirSamAccountNames := fmt.Sprintf("%s/sam_account_credential_stuffing", flareOutputDir)

	// Create the output directory if it doesn't exist
	if err := os.MkdirAll(credStuffingDir, 0750); err != nil {
		return utils.LogError(err)
	}
	if err := os.MkdirAll(credStuffingDirSamAccountNames, 0750); err != nil {
		return utils.LogError(err)
	}

	// Map to store unique credential pairs for each account name
	userMap := make(map[string]map[string]bool)
	userIDMap := make(map[string]map[string]bool)

	// Group unique credential pairs by accountName
	for _, d := range data.Data {
		for _, cred := range d.BreachData {
			if cred.Password == "" { // Skip if the password is empty
				continue
			}
			if _, exists := userMap[d.Properties.Name]; !exists {
				userMap[d.Properties.Name] = make(map[string]bool)
			}
			userMap[d.Properties.Name][cred.Password] = true

			// now do SamAccountName
			if _, exists := userIDMap[d.Properties.Samaccountname]; !exists {
				userIDMap[d.Properties.Samaccountname] = make(map[string]bool)
			}
			userIDMap[d.Properties.Samaccountname][cred.Password] = true
		}

	}

	// Create waves based on the number of unique passwords per accountName
	waves := make(map[int][]string)
	for accountName, passwords := range userMap {
		passwordList := getSortedKeys(passwords)
		for i, password := range passwordList {
			entry := fmt.Sprintf("%s:%s", accountName, password)
			waves[i] = append(waves[i], entry)
		}
	}

	// Create waves based on the number of unique passwords per SamAccountName
	wavesSamiYam := make(map[int][]string)
	for samAccountName, passwords := range userIDMap {
		passwordList := getSortedKeys(passwords)
		for i, password := range passwordList {
			entry := fmt.Sprintf("%s:%s", samAccountName, password)
			wavesSamiYam[i] = append(wavesSamiYam[i], entry)
		}
	}

	// Write each wave's unique credentials into a separate file
	utils.InfoLabelWithColorf("FLARE LEAK DATA", "cyan", "Generating cleartext credential stuffing files excluding common hashes and likely encrypted values")
	for waveIndex, entries := range waves {
		waveNumber := waveIndex + 1
		credStuffingFilePath := fmt.Sprintf("%s/wave-%d.txt", credStuffingDir, waveNumber)

		// Sort the entries for consistency
		sort.Strings(entries)

		// Write the entries to the file
		utils.InfoLabelWithColorf("FLARE LEAK DATA", "magenta", "Writing %d unique credential stuffing pairs to: %s", len(entries), credStuffingFilePath)
		if err := utils.WriteLines(entries, credStuffingFilePath); err != nil {
			return utils.LogError(err)
		}
	}

	// Write each wave's unique credentials into a separate file for SamAccountNames
	utils.InfoLabelWithColorf("FLARE LEAK DATA", "cyan", "Generating cleartext credential stuffing files for SamAccountNames excluding common hashes and likely encrypted values")
	for waveIndex, entries := range wavesSamiYam {
		waveNumber := waveIndex + 1
		credStuffingFilePath := fmt.Sprintf("%s/wave-%d.txt", credStuffingDirSamAccountNames, waveNumber)

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
