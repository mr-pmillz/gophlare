package bloodhound

import (
	"encoding/json"
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/mr-pmillz/gophlare/utils"
	"log"
	"os"
	"time"
)

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
		case utils.IsHash(v.Hash):
			flareData.Hash = v.Hash
		case utils.IsLikelyAnEncryptedValue(v.Hash):
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

// ParseFlareLeaksByDomainFile ...
func ParseFlareLeaksByDomainFile(filePath string) (*FlareCreds, error) {
	var data phlare.FlareSearchCredentials
	if err := utils.UnmarshalJSONFile(filePath, &data); err != nil {
		return nil, err
	}
	flareCreds := setFlareCredentialPairsStructFromFlareData(&data)

	return flareCreds, nil
}

// ParseOldBloodHoundUsersFile ...
func ParseOldBloodHoundUsersFile(filePath string) (*OldBloodHoundUserNodes, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data OldBloodHoundUserNodes
	if err = json.NewDecoder(file).Decode(&data); err != nil {
		log.Println("Error parsing JSON")
		return nil, err
	}

	return &data, nil
}

// ParseBloodHoundUsersFile ...
func ParseBloodHoundUsersFile(filePath string) (*BHCEUserData, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data BHCEUserData
	if err = json.NewDecoder(file).Decode(&data); err != nil {
		log.Println("Error parsing JSON")
		return nil, err
	}

	return &data, nil
}
