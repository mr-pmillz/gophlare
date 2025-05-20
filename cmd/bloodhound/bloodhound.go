package bloodhound

import (
	"fmt"
	"github.com/mr-pmillz/gophlare/bloodhound"
	"github.com/mr-pmillz/gophlare/utils"
	"strings"
	"sync"
)

// UpdateADUsersMetadata processes user data against leak data with optimized performance
func UpdateADUsersMetadata(opts *bloodhound.Options) error {
	// bhData, err := bloodhound.ParseBloodHoundUsersFile(opts.BloodhoundUsersJSONFile)
	// if err != nil {
	//	return utils.LogError(err)
	// }

	// TODO: get goldmine data

	// Parse leak data
	flareLeaksByDomainData, err := bloodhound.ParseFlareLeaksByDomainFile(opts.FlareCredsByDomainJSONFile)
	if err != nil {
		return utils.LogError(err)
	}

	// Set up a neo4j database connection
	neo4jOpts := bloodhound.NewNeo4jDBOptions(opts.Neo4jHost, opts.Neo4jPort, opts.Neo4jUser, opts.Neo4jPassword)
	db, err := bloodhound.NewNeo4jDBConnection(neo4jOpts)
	if err != nil {
		return utils.LogError(err)
	}

	// Get user data
	users, err := db.GetAllUserData()
	if err != nil {
		return utils.LogError(err)
	}

	// Create an optimized map of leak data for O(1) lookups
	// Map structure: domain -> email -> hash
	leaksByDomainAndIdentity := make(map[string]map[string]string)
	for _, leakData := range flareLeaksByDomainData.Items {
		domainKey := strings.ToLower(leakData.Domain)
		identityKey := strings.ToLower(leakData.IdentityName)

		if _, exists := leaksByDomainAndIdentity[domainKey]; !exists {
			leaksByDomainAndIdentity[domainKey] = make(map[string]string)
		}
		leaksByDomainAndIdentity[domainKey][identityKey] = leakData.Hash
	}

	// Determine whether to use parallel processing based on data size
	const numWorkers = 4
	const thresholdForParallel = 1000 // Arbitrary threshold, adjust based on performance testing

	// Use parallel processing for large datasets
	if len(users.Data) > thresholdForParallel {
		return processUsersInParallel(users.Data, leaksByDomainAndIdentity, numWorkers)
	}

	// For smaller datasets, use the optimized sequential approach
	return processUsersSequentially(users.Data, leaksByDomainAndIdentity)
}

// processUsersSequentially processes users in a single thread with map lookups
func processUsersSequentially(users []bloodhound.Data, leaksByDomainAndIdentity map[string]map[string]string) error {
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
			if hash, ok := leaksByDomain[emailKey]; ok {
				fmt.Printf("Email: %s UserID: %s Password: %s\n",
					user.Properties.Email, user.Properties.Name, hash)
			}
		}
	}
	return nil
}

// processUsersInParallel processes users using multiple goroutines for improved performance
func processUsersInParallel(users []bloodhound.Data, leaksByDomainAndIdentity map[string]map[string]string, numWorkers int) error {
	// Split users into chunks for parallel processing
	userChunks := chunkUsers(users, numWorkers)

	var wg sync.WaitGroup
	resultChan := make(chan string, len(users)) // Buffer for all possible results

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
					if hash, ok := leaksByDomain[emailKey]; ok {
						resultChan <- fmt.Sprintf("Email: %s UserID: %s Password: %s",
							user.Properties.Email, user.Properties.Name, hash)
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
		fmt.Println(result)
	}

	return nil
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
