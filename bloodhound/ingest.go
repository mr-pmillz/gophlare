package bloodhound

import (
	"encoding/json"
	valid "github.com/asaskevich/govalidator"
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/mr-pmillz/gophlare/utils"
	"log"
	"os"
	"strings"
	"time"
)

const nullString = "null"

// setFlareCredentialPairsStructFromHoardClientHostLeaksJSONFileData ...
func setFlareCredentialPairsStructFromHoardClientHostLeaksJSONFileData(data []HoardClientHostLeaksJSONL) *FlareCreds {
	flareCreds := &FlareCreds{}
	for _, cred := range data {
		flareData := FlareCredentialPairs{}
		switch {
		case utils.IsUserID(cred.Username):
			if strings.Contains(cred.Username, "\\") {
				justUserID := strings.Split(cred.Username, "\\")[1]
				flareData.UserID = justUserID
			} else {
				flareData.UserID = cred.Username
			}
		case valid.IsEmail(cred.Username):
			flareData.Email = cred.Username
		}
		flareData.Password = cred.Password
		flareData.ImportedAt = cred.ImportTimestamp
		flareData.Domain = cred.Domain
		flareData.SourceID = cred.ArchiveName
		flareCreds.Data = append(flareCreds.Data, flareData)
	}
	return flareCreds
}

// setFlareCredentialPairsStructFromStealerLogCSVFileData ...
func setFlareCredentialPairsStructFromStealerLogCSVFileData(data *[]StealerLogsCredentialCSVFile) *FlareCreds {
	flareCreds := &FlareCreds{}
	for _, cred := range *data {
		flareData := FlareCredentialPairs{}
		emailDomain := ""
		switch {
		case utils.IsUserID(cred.Username):
			if strings.Contains(cred.Username, "\\") {
				userIDParts := strings.Split(cred.Username, "\\")
				flareData.UserID = userIDParts[1]
				if valid.IsDNSName(userIDParts[0]) {
					flareData.Domain = userIDParts[0]
				}
			} else {
				flareData.UserID = cred.Username
			}
		case valid.IsEmail(cred.Username):
			flareData.Email = cred.Username
			emailDomain = strings.Split(cred.Username, "@")[1]
		default:
			flareData.UserID = cred.Username
		}
		switch {
		case emailDomain == "" && flareData.Domain == "":
			// extract the base domain from the URL
			baseDomain, err := utils.ExtractBaseDomain(cred.URL)
			if err != nil {
				flareData.Domain = ""
			}
			flareData.Domain = baseDomain
		case emailDomain == "" && flareData.Domain != "":
			// Do nothing
		default:
			flareData.Domain = emailDomain
		}
		flareData.Password = cred.Password
		flareCreds.Data = append(flareCreds.Data, flareData)
	}

	return flareCreds
}

// setFlareCredentialPairsStructFromFlareData parses FlareSearchCredentials and maps them to a FlareCreds structure.
func setFlareCredentialPairsStructFromFlareData(data *phlare.FlareSearchCredentials) *FlareCreds {
	flareCreds := &FlareCreds{}
	for _, v := range data.Items {
		flareData := FlareCredentialPairs{}
		flareData.Email = v.IdentityName
		// check if the v.Hash value is a password or a hash...
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

// ParseHostLeaksJSONFile ...
func ParseHostLeaksJSONFile(filePath string) (*FlareCreds, error) {
	// var data HoardClientHostLeaksJSONL
	data, err := utils.UnmarshalJSONLines(filePath, HoardClientHostLeaksJSONL{})
	if err != nil {
		return nil, err
	}
	flareCreds := setFlareCredentialPairsStructFromHoardClientHostLeaksJSONFileData(data.([]HoardClientHostLeaksJSONL))

	return flareCreds, nil
}

// ParseStealerLogsHostLeaksFile ...
func ParseStealerLogsHostLeaksFile(filePath string) (*FlareCreds, error) {
	var data []StealerLogsCredentialCSVFile
	if err := utils.UnmarshalCSVFile(filePath, &data); err != nil {
		return nil, err
	}
	flareCreds := setFlareCredentialPairsStructFromStealerLogCSVFileData(&data)

	return flareCreds, nil
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
