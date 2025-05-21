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
	Password       string
	BreachedAt interface{}
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

// OldBloodHoundUserNodes ...
type OldBloodHoundUserNodes struct {
	Nodes []struct {
		ID    int    `json:"id,omitempty"`
		Type  string `json:"type,omitempty"`
		Label string `json:"label,omitempty"`
		Props struct {
			Sidhistory              []interface{} `json:"sidhistory,omitempty"`
			Description             string        `json:"description,omitempty"`
			Unconstraineddelegation bool          `json:"unconstraineddelegation,omitempty"`
			PathCandidate           bool          `json:"path_candidate,omitempty"`
			Enabled                 bool          `json:"enabled,omitempty"`
			Pwdneverexpires         bool          `json:"pwdneverexpires,omitempty"`
			IsDa                    bool          `json:"is_da,omitempty"`
			IsAdmin                 bool          `json:"is_admin,omitempty"`
			Hasspn                  bool          `json:"hasspn,omitempty"`
			Trustedtoauth           bool          `json:"trustedtoauth,omitempty"`
			Whencreated             int           `json:"whencreated,omitempty"`
			Serviceprincipalnames   []interface{} `json:"serviceprincipalnames,omitempty"`
			Admincount              bool          `json:"admincount,omitempty"`
			IsDag                   bool          `json:"is_dag,omitempty"`
			Lastlogontimestamp      int           `json:"lastlogontimestamp,omitempty"`
			Highvalue               bool          `json:"highvalue,omitempty"`
			Passwordnotreqd         bool          `json:"passwordnotreqd,omitempty"`
			Sensitive               bool          `json:"sensitive,omitempty"`
			Domainsid               string        `json:"domainsid,omitempty"`
			Samaccountname          string        `json:"samaccountname,omitempty"`
			OuCandidate             bool          `json:"ou_candidate,omitempty"`
			Owned                   bool          `json:"owned,omitempty"`
			Displayname             string        `json:"displayname,omitempty"`
			Domain                  string        `json:"domain,omitempty"`
			Pwdlastset              int           `json:"pwdlastset,omitempty"`
			Lastlogon               int           `json:"lastlogon,omitempty"`
			Name                    string        `json:"name,omitempty"`
			Distinguishedname       string        `json:"distinguishedname,omitempty"`
			Objectid                string        `json:"objectid,omitempty"`
			IsDaDc                  bool          `json:"is_da_dc,omitempty"`
			Dontreqpreauth          bool          `json:"dontreqpreauth,omitempty"`
			Logonscript             string        `json:"logonscript,omitempty"`
		} `json:"props,omitempty"`
		Glyphs []interface{} `json:"glyphs,omitempty"`
		Folded struct {
			Nodes []interface{} `json:"nodes,omitempty"`
			Edges []interface{} `json:"edges,omitempty"`
		} `json:"folded,omitempty"`
		X         float64 `json:"x,omitempty"`
		Y         float64 `json:"y,omitempty"`
		Objectid  string  `json:"objectid,omitempty"`
		Notowned  bool    `json:"notowned,omitempty"`
		Highvalue bool    `json:"highvalue,omitempty"`
		TypeUser  bool    `json:"type_user,omitempty"`
	} `json:"nodes,omitempty"`
	Edges []interface{} `json:"edges,omitempty"`
}

// LinkedInScrape represents the LinkedIn Scrape JSON data from Goldmine
type LinkedInScrape struct {
	Email                  interface{} `json:"email,omitempty"`
	FacebookID             string      `json:"facebook_id,omitempty"`
	FacebookUsername       string      `json:"facebook_username,omitempty"`
	FirstName              string      `json:"first_name,omitempty"`
	FullName               string      `json:"full_name,omitempty"`
	GithubURL              string      `json:"github_url,omitempty"`
	GithubUsername         string      `json:"github_username,omitempty"`
	JobTitle               string      `json:"job_title,omitempty"`
	LastName               string      `json:"last_name,omitempty"`
	LinkedinCompanyID      string      `json:"linkedin_company_id,omitempty"`
	LinkedinCompanyName    string      `json:"linkedin_company_name,omitempty"`
	LinkedinCompanyWebsite string      `json:"linkedin_company_website,omitempty"`
	LinkedinID             string      `json:"linkedin_id,omitempty"`
	LinkedinSummary        string      `json:"linkedin_summary,omitempty"`
	LinkedinUsername       string      `json:"linkedin_username,omitempty"`
	Location               string      `json:"location,omitempty"`
	MobilePhone            string      `json:"mobile_phone,omitempty"`
	PhoneNumber            string      `json:"phone_number,omitempty"`
	PublishDate            string      `json:"publish_date,omitempty"`
	Sex                    string      `json:"sex,omitempty"`
	TwitterURL             string      `json:"twitter_url,omitempty"`
	TwitterUsername        string      `json:"twitter_username,omitempty"`
}

// GoldmineDataFields represents the Goldmine JSON data fields
type GoldmineDataFields struct {
	NineteenThousandFiveHundredHash string      `json:"19500_hash,omitempty"`
	NineteenThousandFiveHundredSalt string      `json:"19500_salt,omitempty"`
	Address                         interface{} `json:"address,omitempty"`
	Age                             string      `json:"age,omitempty"`
	BcryptHashThree                 string      `json:"bcrypt_hash_3,omitempty"`
	BcryptHashTwo                   string      `json:"bcrypt_hash_2,omitempty"`
	BcryptHash                      string      `json:"bcrypt_hash,omitempty"`
	BcryptSalt                      string      `json:"bcrypt_salt,omitempty"`
	BirthDate                       string      `json:"birth_date,omitempty"`
	BreachedSite                    string      `json:"breached_site,omitempty"`
	City                            interface{} `json:"city,omitempty"`
	Country                         interface{} `json:"country,omitempty"`
	DateOfBirth                     string      `json:"date_of_birth,omitempty"`
	Device                          string      `json:"device,omitempty"`
	DeviceVersion                   string      `json:"device_version,omitempty"`
	Domain                          string      `json:"domain,omitempty"`
	Email                           interface{} `json:"email,omitempty"`
	EmailListSite                   string      `json:"email_list_site,omitempty"`
	EncPassword                     string      `json:"enc_password,omitempty"`
	FacebookID                      string      `json:"facebook_id,omitempty"`
	FacebookToken                   string      `json:"facebook_token,omitempty"`
	FacebookUsername                string      `json:"facebook_username,omitempty"`
	Fbid                            string      `json:"fbid,omitempty"`
	FirstName                       string      `json:"first_name,omitempty"`
	FullName                        string      `json:"full_name,omitempty"`
	Gender                          string      `json:"gender,omitempty"`
	GithubURL                       string      `json:"github_url,omitempty"`
	GithubUsername                  string      `json:"github_username,omitempty"`
	Host                            string      `json:"host,omitempty"`
	ImportTimestamp                 string      `json:"import_timestamp,omitempty"`
	InstagramID                     string      `json:"instagram_id,omitempty"`
	InstagramToken                  string      `json:"instagram_token,omitempty"`
	IP                              interface{} `json:"ip,omitempty"`
	JobTitle                        interface{} `json:"job_title,omitempty"`
	Language                        string      `json:"language,omitempty"`
	LastLoginDate                   string      `json:"last_login_date,omitempty"`
	LastName                        string      `json:"last_name,omitempty"`
	LastPasswordChangeDate          string      `json:"last_password_change_date,omitempty"`
	LegacyPassword                  string      `json:"legacy_password,omitempty"`
	LicensePlates                   []string    `json:"license_plates,omitempty"`
	LinkedinCompanyID               string      `json:"linkedin_company_id,omitempty"`
	LinkedinCompanyName             string      `json:"linkedin_company_name,omitempty"`
	LinkedinCompanyWebsite          string      `json:"linkedin_company_website,omitempty"`
	LinkedinID                      string      `json:"linkedin_id,omitempty"`
	LinkedinSummary                 string      `json:"linkedin_summary,omitempty"`
	LinkedinURL                     string      `json:"linkedin_url,omitempty"`
	LinkedinUsername                string      `json:"linkedin_username,omitempty"`
	Location                        string      `json:"location,omitempty"`
	Md5Hash                         string      `json:"md5_hash,omitempty"`
	MiddleName                      string      `json:"middle_name,omitempty"`
	MobilePhone                     string      `json:"mobile_phone,omitempty"`
	Name                            interface{} `json:"name,omitempty"`
	NitroFiles                      []string    `json:"nitro_files,omitempty"`
	NitroID                         interface{} `json:"nitro_id,omitempty"`
	Password                        string      `json:"password,omitempty"`
	PasswordFirst10                 string      `json:"password_first10,omitempty"`
	PasswordHash                    string      `json:"password_hash,omitempty"`
	PasswordHint                    string      `json:"password_hint,omitempty"`
	Phone1                          string      `json:"phone1,omitempty"`
	PhoneNumber                     interface{} `json:"phone_number,omitempty"`
	PlainSalt                       string      `json:"plainsalt,omitempty"`
	PublishDate                     string      `json:"publish_date,omitempty"`
	SaltedSha1Hash                  string      `json:"salted_sha1_hash,omitempty"`
	SaltedSha512Hash                string      `json:"salted_sha512_hash,omitempty"`
	ScryptHash                      string      `json:"scrypt_hash,omitempty"`
	Sex                             string      `json:"sex,omitempty"`
	Sha1Hash                        string      `json:"sha1_hash,omitempty"`
	Sha1HashSalted                  string      `json:"sha1_hash_salted,omitempty"`
	Sha1Salted                      string      `json:"sha1_salted,omitempty"`
	Software                        string      `json:"software,omitempty"`
	State                           interface{} `json:"state,omitempty"`
	TwitterCreated                  string      `json:"twitter_created,omitempty"`
	TwitterDisplayName              string      `json:"twitter_display_name,omitempty"`
	TwitterFollowers                int         `json:"twitter_followers,omitempty"`
	TwitterID                       string      `json:"twitter_id,omitempty"`
	TwitterURL                      string      `json:"twitter_url,omitempty"`
	TwitterUsername                 string      `json:"twitter_username,omitempty"`
	UnidentifiedField               string      `json:"unidentified_field,omitempty"`
	URL                             string      `json:"url,omitempty"`
	Username                        string      `json:"username,omitempty"`
	UserAgent                       string      `json:"user_agent,omitempty"`
	UserID                          string      `json:"user_id,omitempty"`
	VehicleDescriptions             []string    `json:"vehicle_descriptions,omitempty"`
	ZipCode                         string      `json:"zip_code,omitempty"`
}
