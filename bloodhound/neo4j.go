package bloodhound

import (
	"fmt"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

type Neo4jDB struct {
	Conn    *neo4j.Session
	Options *Neo4jDBOptions
}

// Neo4jDBOptions ...
type Neo4jDBOptions struct {
	Host     string
	Port     string
	User     string
	Password string
}

// NewNeo4jDBOptions creates a new Neo4jDBOptions instance with the provided connection parameters
func NewNeo4jDBOptions(host, port, user, password string) *Neo4jDBOptions {
	return &Neo4jDBOptions{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
	}
}

// NewNeo4jDBConnection ...
func NewNeo4jDBConnection(neo4jOpts *Neo4jDBOptions) (*Neo4jDB, error) {
	dbURI := fmt.Sprintf("neo4j://%s:%s", neo4jOpts.Host, neo4jOpts.Port)
	driver, err := neo4j.NewDriver(dbURI, neo4j.BasicAuth(neo4jOpts.User, neo4jOpts.Password, ""))
	if err != nil {
		return nil, utils.LogError(err)
	}

	neo4jSession := driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	return &Neo4jDB{
		Conn:    &neo4jSession,
		Options: neo4jOpts,
	}, err
}

// AddUserMetadata adds custom metadata to a user in neo4j
func (db *Neo4jDB) AddUserMetadata(username string, metadata map[string]interface{}) error {
	session := *db.Conn
	props := make(map[string]interface{})
	for k, v := range metadata {
		props[k] = v
	}

	_, err := session.Run(
		"MATCH (u:User {name: $username}) SET u += $props",
		map[string]interface{}{
			"username": username,
			"props":    props,
		})
	if err != nil {
		return utils.LogError(err)
	}
	return nil
}

// GetAllUserData ...
//
//nolint:gocognit
func (db *Neo4jDB) GetAllUserData() (*BHCEUserData, error) {
	session := *db.Conn
	result, err := session.Run("MATCH (u:User) RETURN u", nil)
	if err != nil {
		return nil, err // or utils.LogError(err)
	}

	var userList BHCEUserData

	for result.Next() {
		record := result.Record()
		user, _ := record.Get("u")
		props := user.(neo4j.Node).Props

		var userData Data

		// Map properties safely, use type assertions as needed
		if v, ok := props["domain"].(string); ok {
			userData.Properties.Domain = v
		}
		if v, ok := props["name"].(string); ok {
			userData.Properties.Name = v
		}
		if v, ok := props["distinguishedname"].(string); ok {
			userData.Properties.Distinguishedname = v
		}
		if v, ok := props["domainsid"].(string); ok {
			userData.Properties.Domainsid = v
		}
		if v, ok := props["samaccountname"].(string); ok {
			userData.Properties.Samaccountname = v
		}
		if v, ok := props["isaclprotected"].(bool); ok {
			userData.Properties.Isaclprotected = v
		}
		if v, ok := props["description"]; ok {
			userData.Properties.Description = v
		}
		if v, ok := props["sensitive"].(bool); ok {
			userData.Properties.Sensitive = v
		}
		if v, ok := props["dontreqpreauth"].(bool); ok {
			userData.Properties.Dontreqpreauth = v
		}
		if v, ok := props["passwordnotreqd"].(bool); ok {
			userData.Properties.Passwordnotreqd = v
		}
		if v, ok := props["unconstraineddelegation"].(bool); ok {
			userData.Properties.Unconstraineddelegation = v
		}
		if v, ok := props["pwdneverexpires"].(bool); ok {
			userData.Properties.Pwdneverexpires = v
		}
		if v, ok := props["enabled"].(bool); ok {
			userData.Properties.Enabled = v
		}
		if v, ok := props["trustedtoauth"].(bool); ok {
			userData.Properties.Trustedtoauth = v
		}
		if v, ok := props["whencreated"].(float64); ok {
			userData.Properties.Whencreated = int64(v)
		}
		if v, ok := props["lastlogon"].(float64); ok {
			userData.Properties.Lastlogon = int64(v)
		}
		if v, ok := props["lastlogontimestamp"].(float64); ok {
			userData.Properties.Lastlogontimestamp = int64(v)
		}
		if v, ok := props["pwdlastset"].(float64); ok {
			userData.Properties.Pwdlastset = int64(v)
		}
		if v, ok := props["serviceprincipalnames"].([]interface{}); ok {
			userData.Properties.Serviceprincipalnames = v
		}
		if v, ok := props["hasspn"].(bool); ok {
			userData.Properties.Hasspn = v
		}
		if v, ok := props["displayname"].(string); ok {
			userData.Properties.Displayname = v
		}
		if v, ok := props["email"].(string); ok {
			userData.Properties.Email = v
		}
		if v, ok := props["title"].(string); ok {
			userData.Properties.Title = v
		}
		if v, ok := props["homedirectory"].(string); ok {
			userData.Properties.Homedirectory = v
		}
		if v, ok := props["userpassword"].(string); ok {
			userData.Properties.Userpassword = v
		}
		if v, ok := props["unixpassword"].(string); ok {
			userData.Properties.Unixpassword = v
		}
		if v, ok := props["unicodepassword"].(string); ok {
			userData.Properties.Unicodepassword = v
		}
		if v, ok := props["sfupassword"].(string); ok {
			userData.Properties.Sfupassword = v
		}
		if v, ok := props["logonscript"].(string); ok {
			userData.Properties.Logonscript = v
		}
		if v, ok := props["admincount"].(bool); ok {
			userData.Properties.Admincount = v
		}
		if v, ok := props["sidhistory"].([]interface{}); ok {
			userData.Properties.Sidhistory = v
		}
		if v, ok := props["objectid"].(string); ok {
			userData.Properties.ObjectID = v
		}

		// userData.AllowedToDelegate = ...
		// userData.PrimaryGroupSID = ...
		// userData.HasSIDHistory = ...
		// userData.SPNTargets = ...
		// userData.Aces = ...
		// userData.Meta = ...

		userList.Data = append(userList.Data, userData)
	}

	resultStruct := &BHCEUserData{
		Data: userList.Data,
	}
	return resultStruct, nil
}
