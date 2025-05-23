package bloodhound

import "time"

// BHCEUserData ...
type BHCEUserData struct {
	Data []Data `json:"data,omitempty"`
}
type Properties struct {
	Domain                       string        `json:"domain,omitempty"`
	Name                         string        `json:"name,omitempty"`
	Distinguishedname            string        `json:"distinguishedname,omitempty"`
	Domainsid                    string        `json:"domainsid,omitempty"`
	Samaccountname               string        `json:"samaccountname,omitempty"`
	Isaclprotected               bool          `json:"isaclprotected,omitempty"`
	Description                  interface{}   `json:"description,omitempty"`
	Whencreated                  int64         `json:"whencreated,omitempty"`
	Sensitive                    bool          `json:"sensitive,omitempty"`
	Dontreqpreauth               bool          `json:"dontreqpreauth,omitempty"`
	Passwordnotreqd              bool          `json:"passwordnotreqd,omitempty"`
	Unconstraineddelegation      bool          `json:"unconstraineddelegation,omitempty"`
	Pwdneverexpires              bool          `json:"pwdneverexpires,omitempty"`
	Enabled                      bool          `json:"enabled,omitempty"`
	Trustedtoauth                bool          `json:"trustedtoauth,omitempty"`
	Lastlogon                    int64         `json:"lastlogon,omitempty"`
	Lastlogontimestamp           int64         `json:"lastlogontimestamp,omitempty"`
	Pwdlastset                   int64         `json:"pwdlastset,omitempty"`
	Serviceprincipalnames        []interface{} `json:"serviceprincipalnames,omitempty"`
	Hasspn                       bool          `json:"hasspn,omitempty"`
	Displayname                  string        `json:"displayname,omitempty"`
	Email                        string        `json:"email,omitempty"`
	Title                        string        `json:"title,omitempty"`
	Homedirectory                string        `json:"homedirectory,omitempty"`
	Userpassword                 string        `json:"userpassword,omitempty"`
	Unixpassword                 string        `json:"unixpassword,omitempty"`
	Unicodepassword              string        `json:"unicodepassword,omitempty"`
	Sfupassword                  string        `json:"sfupassword,omitempty"`
	Logonscript                  string        `json:"logonscript,omitempty"`
	Admincount                   bool          `json:"admincount,omitempty"`
	Sidhistory                   []interface{} `json:"sidhistory,omitempty"`
	ObjectID                     interface{}   `json:"objectid,omitempty"`
	HasBreachData                bool          `json:"hasbreachdata,omitempty"`
	HasBreachDataAfterPwdLastSet bool          `json:"hasbreachdataafterpwdlastset,omitempty"`
	BreachedAt                   float64       `json:"breachedat,omitempty"`
	BreachSources                []string      `json:"breachsource,omitempty"`
	PwdLastSetBeforeBreach       string        `json:"pwdlastsetbeforebreach,omitempty"`
}
type Aces struct {
	PrincipalSID  string `json:"PrincipalSID,omitempty"`
	PrincipalType string `json:"PrincipalType,omitempty"`
	RightName     string `json:"RightName,omitempty"`
	IsInherited   bool   `json:"IsInherited,omitempty"`
}
type Meta struct {
	Methods int    `json:"methods,omitempty"`
	Type    string `json:"type,omitempty"`
	Count   int    `json:"count,omitempty"`
	Version int    `json:"version,omitempty"`
}
type Data struct {
	Properties        Properties    `json:"Properties,omitempty"`
	AllowedToDelegate []interface{} `json:"AllowedToDelegate,omitempty"`
	PrimaryGroupSID   string        `json:"PrimaryGroupSID,omitempty"`
	HasSIDHistory     []interface{} `json:"HasSIDHistory,omitempty"`
	SPNTargets        []interface{} `json:"SPNTargets,omitempty"`
	Aces              []Aces        `json:"Aces,omitempty"`
	Meta              Meta          `json:"meta,omitempty"`
	BreachData        []LeakInfo    `json:"breachData,omitempty"` // Custom field for breach data correlation
}

type LeakInfo struct {
	Password   string
	Hash       string
	BreachedAt interface{}
	SourceID   string
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
