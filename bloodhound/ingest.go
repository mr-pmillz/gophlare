package bloodhound

import (
	"encoding/json"
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/mr-pmillz/gophlare/utils"
	"log"
	"os"
)

// ParseFlareLeaksByDomainFile ...
func ParseFlareLeaksByDomainFile(filePath string) (*phlare.FlareSearchCredentials, error) {
	var data phlare.FlareSearchCredentials
	if err := utils.UnmarshalJSONFile(filePath, &data); err != nil {
		return nil, err
	}

	return &data, nil
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
