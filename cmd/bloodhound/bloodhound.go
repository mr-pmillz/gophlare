package bloodhound

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/mr-pmillz/gophlare/bloodhound"
	"github.com/mr-pmillz/gophlare/utils"
)

// ProcessData ...
func ProcessData(opts *bloodhound.Options) error {
	// correlate the data
	correlatedBHUserData, err := CorrelateLeakDataWithBloodHoundData(opts)
	if err != nil {
		return utils.LogError(err)
	}
	if len(correlatedBHUserData.Data) == 0 {
		utils.LogWarningf("No matching correlatable breach data found for Active Directory users..")
		return nil
	}
	if err = WriteCredStuffingFiles(correlatedBHUserData, opts.OutputDir); err != nil {
		return utils.LogError(err)
	}
	// write updated BloodHound data to CSV file for review
	updatedBHUserDataCSVFile := fmt.Sprintf("%s/bloodhound-users-flare-correlation.csv", opts.OutputDir)
	if err = utils.WriteInterfaceToCSV(correlatedBHUserData.Data, updatedBHUserDataCSVFile); err != nil {
		return utils.LogError(err)
	}
	// convert csv file to xlsx
	updatedBHUserDataXLSFile := fmt.Sprintf("%s/bloodhound-users-flare-correlation.xlsx", opts.OutputDir)
	if err = utils.CSVsToExcel([]string{updatedBHUserDataCSVFile}, updatedBHUserDataXLSFile); err != nil {
		return utils.LogError(err)
	}

	if opts.UpdateBloodhound {
		if err = UpdateBloodHoundUserData(opts, correlatedBHUserData); err != nil {
			return utils.LogError(err)
		}
		// create custom Bloodhound queries for leak data
		if err = CreateShortestPathsFromBreachedCredentialsQueriesBHCE(opts); err != nil {
			return utils.LogError(err)
		}
	}

	return nil
}

// CreateShortestPathsFromBreachedCredentialsQueriesBHCE ...
func CreateShortestPathsFromBreachedCredentialsQueriesBHCE(opts *bloodhound.Options) error {
	bhAPIOpts := bloodhound.NewBloodHoundAPIOptions(opts.BloodhoundServerURL, opts.BloodhoundUser, opts.BloodhoundPassword)
	bhClient, err := bloodhound.NewBloodHoundAPIClient(bhAPIOpts)
	if err != nil {
		return utils.LogError(err)
	}

	utils.InfoLabelWithColorf("BLOODHOUND API", "cyan", "Creating custom Bloodhound queries for leak data")
	shortestPathsToDomainAdminsFromBreachedCredentialsAfterPwdLastSetQueryName := "Shortest Paths to Domain Admins from Breached Credential After PwdLastSet Users"
	shortestPathsToDomainAdminsFromBreachedCredentialsAfterPwdLastSetQuery := "MATCH p=shortestPath((t:Group)<-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|Contains|DCFor|TrustedBy*1..]-(s:Base)) WHERE t.objectid ENDS WITH '-512' AND s.hasbreachdata = true AND s.hasbreachdataafterpwdlastset = true AND s<>t RETURN p LIMIT 1000"

	if err = bhClient.SaveCustomQueryBloodHoundCE(shortestPathsToDomainAdminsFromBreachedCredentialsAfterPwdLastSetQueryName, shortestPathsToDomainAdminsFromBreachedCredentialsAfterPwdLastSetQuery); err != nil {
		return utils.LogError(err)
	}

	shortestPathsToDomainAdminsFromBreachedCredentialsQueryName := "Shortest Paths to Domains Admin from Breached Credential Users"
	shortestPathsToDomainAdminsFromBreachedCredentialsQuery := "MATCH p=shortestPath((t:Group)<-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|Contains|DCFor|TrustedBy*1..]-(s:Base)) WHERE t.objectid ENDS WITH '-512' AND s.hasbreachdata = true AND s<>t RETURN p LIMIT 1000"

	if err = bhClient.SaveCustomQueryBloodHoundCE(shortestPathsToDomainAdminsFromBreachedCredentialsQueryName, shortestPathsToDomainAdminsFromBreachedCredentialsQuery); err != nil {
		return utils.LogError(err)
	}

	shortestPathsFromBreachedCredentialsAfterPwdLastSetQueryName := "Shortest Paths from Breached Credential After PwdLastSet Users"
	shortestPathsFromBreachedCredentialsAfterPwdLastSetQuery := "MATCH p=shortestPath((s)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|Contains|DCFor|TrustedBy*1..]->(t)) WHERE s.hasbreachdata = true AND s.hasbreachdataafterpwdlastset = true AND s<>t RETURN p LIMIT 1000"
	if err = bhClient.SaveCustomQueryBloodHoundCE(shortestPathsFromBreachedCredentialsAfterPwdLastSetQueryName, shortestPathsFromBreachedCredentialsAfterPwdLastSetQuery); err != nil {
		return utils.LogError(err)
	}

	shortestPathsFromBreachedCredentialsQueryName := "Shortest Paths from Breached Credentials"
	shortestPathsFromBreachedCredentialsQuery := "MATCH p=shortestPath((s)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|WriteOwnerLimitedRights|OwnsLimitedRights|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|Contains|DCFor|TrustedBy*1..]->(t)) WHERE s.hasbreachdata = true AND s<>t RETURN p LIMIT 1000"
	if err = bhClient.SaveCustomQueryBloodHoundCE(shortestPathsFromBreachedCredentialsQueryName, shortestPathsFromBreachedCredentialsQuery); err != nil {
		return utils.LogError(err)
	}

	return nil
}

// UpdateBloodHoundUserData ...
func UpdateBloodHoundUserData(opts *bloodhound.Options, data *bloodhound.BHCEUserData) error {
	utils.InfoLabelWithColorf("BLOODHOUND NEO4J", "cyan", "Updating bloodhound neo4j users data with leak data indicators")
	// Set up a neo4j database connection
	neo4jOpts := bloodhound.NewNeo4jDBOptions(opts.Neo4jHost, opts.Neo4jPort, opts.Neo4jUser, opts.Neo4jPassword)
	db, err := bloodhound.NewNeo4jDBConnection(neo4jOpts)
	if err != nil {
		return utils.LogError(err)
	}

	for _, user := range data.Data {
		markUserAsPotentiallyCompromised := false
		if user.Properties.HasBreachData {
			for _, leak := range user.BreachData {
				if leak.Password != "" {
					markUserAsPotentiallyCompromised = true
				}
			}
			if markUserAsPotentiallyCompromised {
				props := map[string]interface{}{
					"hasbreachdata":                user.Properties.HasBreachData,
					"hasbreachdataafterpwdlastset": user.Properties.HasBreachDataAfterPwdLastSet,
					"pwdlastsetbeforebreach":       user.Properties.PwdLastSetBeforeBreach,
					"breachedat":                   user.Properties.BreachedAt,
					"breachsources":                user.Properties.BreachSources,
				}
				if err = db.AddUserMetadata(user.Properties.Name, props); err != nil {
					return utils.LogError(err)
				}
			}
		}
	}

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
	userIDBruteForcingOutputTextFile := fmt.Sprintf("%s/userID-brute-forcing.txt", outputDir)
	userIDNoAtDomainBruteForcingOutputTextFile := fmt.Sprintf("%s/SamAccountName-brute-forcing.txt", outputDir)
	if err := utils.WriteLines(utils.SortUnique(lines), userIDBruteForcingOutputTextFile); err != nil {
		return utils.LogError(err)
	}
	if err := utils.WriteLines(utils.SortUnique(linesNoAtDomain), userIDNoAtDomainBruteForcingOutputTextFile); err != nil {
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
	// Parse leak data
	utils.InfoLabelWithColorf("GOPHLARE", "cyan", "Processing leak data")
	flareLeaksByDomainData, err := bloodhound.ParseFlareLeaksByDomainFile(opts.FlareCredsByDomainJSONFile)
	if err != nil {
		return nil, utils.LogError(err)
	}

	if opts.StealerLogsLeaksCSVFile != "" {
		stealerLogLeaksByDomainData, err := bloodhound.ParseStealerLogsHostLeaksFile(opts.StealerLogsLeaksCSVFile)
		if err != nil {
			return nil, utils.LogError(err)
		}
		flareLeaksByDomainData.Data = append(flareLeaksByDomainData.Data, stealerLogLeaksByDomainData.Data...)
	}

	if opts.HostLeaksJSONFile != "" {
		hoardClientStealerLogLeaksByDomainData, err := bloodhound.ParseHostLeaksJSONFile(opts.HostLeaksJSONFile)
		if err != nil {
			return nil, utils.LogError(err)
		}
		flareLeaksByDomainData.Data = append(flareLeaksByDomainData.Data, hoardClientStealerLogLeaksByDomainData.Data...)
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
		utils.InfoLabelWithColorf("BLOODHOUND NEO4J", "cyan", "Getting bloodhound neo4j users data")
		users, err := db.GetAllUserData()
		if err != nil {
			return nil, utils.LogError(err)
		}
		bhUsersData = users
	}

	utils.InfoLabelWithColorf("FLAREHOUND", "cyan", "Correlating data")
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
		switch {
		case leakData.Domain == "" && leakData.Email == "" && leakData.UserID != "":
			// Do nothing
		default:
			domainKey := strings.ToLower(leakData.Domain)
			identityKey := strings.ToLower(leakData.Email)

			if _, exists := leaksByDomainAndIdentity[domainKey]; !exists {
				leaksByDomainAndIdentity[domainKey] = make(map[string][]bloodhound.LeakInfo)
			}
			leaksByDomainAndIdentity[domainKey][identityKey] = append(
				leaksByDomainAndIdentity[domainKey][identityKey],
				bloodhound.LeakInfo{
					Password:   leakData.Password,
					Hash:       leakData.Hash,
					BreachedAt: leakData.BreachedAt,
					SourceID:   leakData.SourceID,
				},
			)
		}
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
		breachedAtEpochDates := make([]interface{}, 0)
		breachSourceIDs := make([]string, 0)

		// Check if we have leaks for this domain and email with O(1) lookups
		if leaksByDomain, ok := leaksByDomainAndIdentity[domainKey]; ok {
			for _, leak := range leaksByDomain[emailKey] {
				user.BreachData = append(user.BreachData, bloodhound.LeakInfo{
					Password:   leak.Password,
					Hash:       leak.Hash,
					BreachedAt: leak.BreachedAt,
					SourceID:   leak.SourceID,
				})
				breachedAtEpochDates = append(breachedAtEpochDates, leak.BreachedAt)
				breachSourceIDs = append(breachSourceIDs, leak.SourceID)
			}
			if len(user.BreachData) > 0 {
				user.Properties.HasBreachData = true
				user.Properties.BreachSources = utils.SortUnique(breachSourceIDs)
				latestEpoch, err := utils.FindMostRecentEpoch(breachedAtEpochDates)
				if err != nil {
					user.Properties.HasBreachDataAfterPwdLastSet = false
					user.Properties.PwdLastSetBeforeBreach = "0"
					updatedUsersData = append(updatedUsersData, user)
					continue
				}
				latestEpochFloat64, err := utils.EpochToFloat64(latestEpoch)
				if err != nil {
					user.Properties.HasBreachDataAfterPwdLastSet = false
					user.Properties.PwdLastSetBeforeBreach = "0"
					updatedUsersData = append(updatedUsersData, user)
					continue
				}
				user.Properties.BreachedAt = latestEpochFloat64
				breachHappenedAfterPWLastSetDate, pwLastSetSinceBreach, err := utils.CompareBreachedAtToPasswordLastSetDate(latestEpoch, user.Properties.Pwdlastset)
				if err != nil {
					user.Properties.HasBreachDataAfterPwdLastSet = false
					user.Properties.PwdLastSetBeforeBreach = "0"
					updatedUsersData = append(updatedUsersData, user)
					continue
				}
				user.Properties.HasBreachDataAfterPwdLastSet = breachHappenedAfterPWLastSetDate
				user.Properties.PwdLastSetBeforeBreach = pwLastSetSinceBreach
			} else {
				user.Properties.HasBreachData = false
			}
			updatedUsersData = append(updatedUsersData, user)
		}
	}
	return &updatedUsersData, nil
}

// processUsersInParallel processes users using multiple goroutines for improved performance
//
//nolint:gocognit
//nolint:dupl
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
				breachedAtEpochDates := make([]interface{}, 0)
				breachSourceIDs := make([]string, 0)

				// Check if we have leaks for this domain and email with O(1) lookups
				if leaksByDomain, ok := leaksByDomainAndIdentity[domainKey]; ok { //nolint:dupl
					for _, leak := range leaksByDomain[emailKey] {
						user.BreachData = append(user.BreachData, bloodhound.LeakInfo{
							Password:   leak.Password,
							Hash:       leak.Hash,
							BreachedAt: leak.BreachedAt,
						})
						breachedAtEpochDates = append(breachedAtEpochDates, leak.BreachedAt)
						breachSourceIDs = append(breachSourceIDs, leak.SourceID)
					}
					if len(user.BreachData) > 0 {
						user.Properties.HasBreachData = true
						user.Properties.BreachSources = utils.SortUnique(breachSourceIDs)
						latestEpoch, err := utils.FindMostRecentEpoch(breachedAtEpochDates)
						if err != nil {
							user.Properties.HasBreachDataAfterPwdLastSet = false
							user.Properties.PwdLastSetBeforeBreach = "0"
							resultChan <- user
							continue
						}
						latestEpochFloat64, err := utils.EpochToFloat64(latestEpoch)
						if err != nil {
							user.Properties.HasBreachDataAfterPwdLastSet = false
							user.Properties.PwdLastSetBeforeBreach = "0"
							resultChan <- user
							continue
						}
						user.Properties.BreachedAt = latestEpochFloat64
						breachHappenedAfterPWLastSetDate, pwLastSetSinceBreach, err := utils.CompareBreachedAtToPasswordLastSetDate(latestEpoch, user.Properties.Pwdlastset)
						if err != nil {
							user.Properties.HasBreachDataAfterPwdLastSet = false
							user.Properties.PwdLastSetBeforeBreach = "0"
							resultChan <- user
							continue
						}
						user.Properties.HasBreachDataAfterPwdLastSet = breachHappenedAfterPWLastSetDate
						user.Properties.PwdLastSetBeforeBreach = pwLastSetSinceBreach
					} else {
						user.Properties.HasBreachData = false
					}
					resultChan <- user
				} else if strings.Contains(emailKey, "@") {
					emailDomainKeyParts := strings.Split(emailKey, "@")
					emailDomainKey := emailDomainKeyParts[1]
					if leaksByDomain, ok := leaksByDomainAndIdentity[emailDomainKey]; ok { //nolint:dupl
						for _, leak := range leaksByDomain[emailKey] {
							user.BreachData = append(user.BreachData, bloodhound.LeakInfo{
								Password:   leak.Password,
								Hash:       leak.Hash,
								BreachedAt: leak.BreachedAt,
							})
							breachedAtEpochDates = append(breachedAtEpochDates, leak.BreachedAt)
							breachSourceIDs = append(breachSourceIDs, leak.SourceID)
						}
						if len(user.BreachData) > 0 {
							user.Properties.HasBreachData = true
							user.Properties.BreachSources = utils.SortUnique(breachSourceIDs)
							latestEpoch, err := utils.FindMostRecentEpoch(breachedAtEpochDates)
							if err != nil {
								user.Properties.HasBreachDataAfterPwdLastSet = false
								user.Properties.PwdLastSetBeforeBreach = "0"
								resultChan <- user
								continue
							}
							latestEpochFloat64, err := utils.EpochToFloat64(latestEpoch)
							if err != nil {
								user.Properties.HasBreachDataAfterPwdLastSet = false
								user.Properties.PwdLastSetBeforeBreach = "0"
								resultChan <- user
								continue
							}
							user.Properties.BreachedAt = latestEpochFloat64
							breachHappenedAfterPWLastSetDate, pwLastSetSinceBreach, err := utils.CompareBreachedAtToPasswordLastSetDate(latestEpoch, user.Properties.Pwdlastset)
							if err != nil {
								user.Properties.HasBreachDataAfterPwdLastSet = false
								user.Properties.PwdLastSetBeforeBreach = "0"
								resultChan <- user
								continue
							}
							user.Properties.HasBreachDataAfterPwdLastSet = breachHappenedAfterPWLastSetDate
							user.Properties.PwdLastSetBeforeBreach = pwLastSetSinceBreach
						} else {
							user.Properties.HasBreachData = false
						}
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
