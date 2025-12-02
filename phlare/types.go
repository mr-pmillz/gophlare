package phlare

import "time"

// FlareClient ...
type FlareClient struct {
	APIKey           string
	TenantID         int
	Client           *Client
	DefaultUserAgent string
	Token            *string
	TokenExp         *time.Time
	ClientTimeout    int
}

// FlareAuthResponse ...
type FlareAuthResponse struct {
	RefreshTokenExp int64  `json:"refresh_token_exp"`
	Token           string `json:"token"`
}

// FlareSearchCredentialsBodyParams ...
type FlareSearchCredentialsBodyParams struct {
	Size  string           `json:"size,omitempty"`
	From  string           `json:"from,omitempty"`
	Query FlareDomainQuery `json:"query"`
}

// FlareDomainQuery ...
type FlareDomainQuery struct {
	Type string `json:"type"`
	Fqdn string `json:"fqdn"`
}

// FlareSearchCredentialsASTP is the JSON response for the /astp/v2/credentials/_search endpoint
type FlareSearchCredentialsASTP struct {
	Items []struct {
		Domain          string      `json:"domain,omitempty"`
		Hash            string      `json:"hash,omitempty"`
		HashType        interface{} `json:"hash_type,omitempty"`
		ID              int64       `json:"id,omitempty"`
		IdentityName    string      `json:"identity_name,omitempty"`
		ImportedAt      time.Time   `json:"imported_at,omitempty"`
		KnownPasswordID interface{} `json:"known_password_id,omitempty"`
		Source          struct {
			BreachedAt     interface{} `json:"breached_at,omitempty"`
			DescriptionEn  string      `json:"description_en,omitempty"`
			DescriptionFr  string      `json:"description_fr,omitempty"`
			ID             string      `json:"id,omitempty"`
			IsAlertEnabled bool        `json:"is_alert_enabled,omitempty"`
			LeakedAt       interface{} `json:"leaked_at,omitempty"`
			Name           string      `json:"name,omitempty"`
		} `json:"source,omitempty"`
		SourceID string `json:"source_id,omitempty"`
	} `json:"items,omitempty"`
	Next *string `json:"next,omitempty"`
}

// FlareSearchCredentials is the JSON response for the /leaksdb/v2/credentials/_search endpoint
type FlareSearchCredentials struct {
	Items []struct {
		Domain          string      `json:"domain,omitempty"`
		Hash            string      `json:"hash,omitempty"`
		ID              int64       `json:"id,omitempty"`
		IdentityName    string      `json:"identity_name,omitempty"`
		ImportedAt      time.Time   `json:"imported_at,omitempty"`
		KnownPasswordID interface{} `json:"known_password_id,omitempty"`
		Source          struct {
			BreachedAt     interface{} `json:"breached_at,omitempty"`
			DescriptionEn  string      `json:"description_en,omitempty"`
			DescriptionFr  string      `json:"description_fr,omitempty"`
			ID             string      `json:"id,omitempty"`
			IsAlertEnabled bool        `json:"is_alert_enabled,omitempty"`
			LeakedAt       interface{} `json:"leaked_at,omitempty"`
			Name           string      `json:"name,omitempty"`
		} `json:"source,omitempty"`
		SourceID string `json:"source_id,omitempty"`
	} `json:"items,omitempty"`
	Next *string `json:"next,omitempty"`
}

// FlareSearchCookiesBodyParams ...
type FlareSearchCookiesBodyParams struct {
	Domain        string   `json:"domain,omitempty"`         // The exact domain for which you want to search cookies. Subdomains will not be included.
	Size          int      `json:"size,omitempty"`           // The number of results to fetch. (default: 100, max: 500)
	From          string   `json:"from,omitempty"`           // The next value from the last response.
	Names         []string `json:"names,omitempty"`          // A list of names to filter for specific cookies, for example ['session', 'PHPSESSID']. (max: 10)
	Paths         []string `json:"paths,omitempty"`          // A list of paths to filter for specific cookies, for example ['/', '/login']. (max: 10)
	ImportedAfter string   `json:"imported_after,omitempty"` // ISO-formatted datetime string to filter for cookies added to Flare’s database after a given date, for example 2024-10-29T17:50:44.237148+00:00.
	ExpiresAfter  string   `json:"expires_after,omitempty"`  // ISO-formatted datetime string to filter for cookie expiration, for example 2024-10-29T17:50:44.237148+00:00.
}

// FlareSearchCookiesResponse ...
type FlareSearchCookiesResponse struct {
	Items []struct {
		UUID       string    `json:"uuid,omitempty"`
		Domain     string    `json:"domain,omitempty"`
		ExpiresAt  time.Time `json:"expires_at,omitempty"`
		ImportedAt time.Time `json:"imported_at,omitempty"`
		Name       string    `json:"name,omitempty"`
		Path       string    `json:"path,omitempty"`
		EventUID   string    `json:"event_uid,omitempty"`
		Value      string    `json:"value,omitempty"`
	} `json:"items,omitempty"`
	Next *string `json:"next,omitempty"`
}

// FlareEventsGlobalSearchBodyParams ...
type FlareEventsGlobalSearchBodyParams struct {
	Query   Query   `json:"query,omitempty"`
	Size    int     `json:"size,omitempty"`
	From    string  `json:"from,omitempty"` // The next value from the last response.
	Order   string  `json:"order,omitempty"`
	Filters Filters `json:"filters,omitempty"`
}

type Query struct {
	Type        string `json:"type,omitempty"`
	QueryString string `json:"query_string,omitempty"`
}

type EstimatedCreatedAt struct {
	Gt  string `json:"gt,omitempty"`  // Gt Matches values greater than the specified timestamp.: ISO-8601 which is time.RFC3339 (YYYY-MM-DDT00:00:00Z)
	Gte string `json:"gte,omitempty"` // Gte Matches values greater than or equal to the specified timestamp.: ISO-8601 which is time.RFC3339 (YYYY-MM-DDT00:00:00Z)
	Lt  string `json:"lt,omitempty"`  // Lt Matches values lesser than the specified timestamp.: ISO-8601 which is time.RFC3339 (YYYY-MM-DDT00:00:00Z)
	Lte string `json:"lte,omitempty"` // Lte Matches values lesser than or equal to the specified timestamp.: ISO-8601 which is time.RFC3339 (YYYY-MM-DDT00:00:00Z)
}

type Filters struct {
	Severity           []string           `json:"severity,omitempty"` // can be info,low,medium,high,critical
	Type               []string           `json:"type,omitempty"`     // illicit_networks open_web leak domain listing forum_content blog_content blog_post profile chat_message ransomleak infected_devices financial_data bot stealer_log paste social_media source_code source_code_files stack_exchange google service buckets bucket bucket_object
	EstimatedCreatedAt EstimatedCreatedAt `json:"estimated_created_at,omitempty"`
}

// FlareEventsGlobalSearchResults ...
type FlareEventsGlobalSearchResults struct {
	Items []struct {
		Metadata struct {
			EstimatedCreatedAt time.Time `json:"estimated_created_at,omitempty"`
			Type               string    `json:"type,omitempty"`
			UID                string    `json:"uid,omitempty"`
			Severity           string    `json:"severity,omitempty"`
		} `json:"metadata,omitempty"`
		TenantMetadata struct {
			Severity struct {
				Original string `json:"original,omitempty"`
				Override string `json:"override,omitempty"`
			} `json:"severity,omitempty"`
			Tags  []string `json:"tags,omitempty"`
			Notes string   `json:"notes,omitempty"`
		} `json:"tenant_metadata,omitempty"`
		Identifiers []struct {
			ID   int    `json:"id,omitempty"`
			Name string `json:"name,omitempty"`
		} `json:"identifiers,omitempty"`
		Highlights struct {
			Description []string `json:"description,omitempty"`
			Title       []string `json:"title,omitempty"`
		} `json:"highlights,omitempty"`
	} `json:"items,omitempty"`
	Next *string `json:"next,omitempty"`
}

// FlareStealerLogZipFileDownloadResponse ...
type FlareStealerLogZipFileDownloadResponse struct {
	StealerLog struct {
		ExternalURL string `json:"external_url,omitempty"`
	} `json:"stealer_log,omitempty"`
}

// FlareTime is a custom time.Time type that supports unmarshalling additional timestamp formats
type FlareTime struct {
	time.Time
}

// FlareFireworkActivitiesIndexSourceIDv2Response ...
type FlareFireworkActivitiesIndexSourceIDv2Response struct {
	Activity struct {
		Data struct {
			EsID       string      `json:"es_id,omitempty"`
			EsScore    interface{} `json:"es_score,omitempty"`
			Highlights struct {
			} `json:"highlights,omitempty"`
			ID       string `json:"id,omitempty"`
			Index    string `json:"index,omitempty"`
			Metadata struct {
				EstimatedCreatedAt FlareTime   `json:"estimated_created_at,omitempty"`
				EventID            interface{} `json:"event_id,omitempty"`
				FirstCrawledAt     FlareTime   `json:"first_crawled_at,omitempty"`
				LastCrawledAt      FlareTime   `json:"last_crawled_at,omitempty"`
				PayloadDigest      string      `json:"payload_digest,omitempty"`
				ScrapedAt          FlareTime   `json:"scraped_at,omitempty"`
				Source             string      `json:"source,omitempty"`
				CrawledBy          interface{} `json:"crawled_by,omitempty"`
			} `json:"metadata,omitempty"`
			UID         string      `json:"uid,omitempty"`
			URL         interface{} `json:"url,omitempty"`
			BrowserURL  interface{} `json:"browser_url,omitempty"`
			Name        interface{} `json:"name,omitempty"`
			InstalledAt FlareTime   `json:"installed_at,omitempty"`
			UpdatedAt   interface{} `json:"updated_at,omitempty"`
			SellerID    interface{} `json:"seller_id,omitempty"`
			Isp         interface{} `json:"isp,omitempty"`
			Information interface{} `json:"information,omitempty"`
			Credentials []struct {
				URL         string `json:"url,omitempty"`
				Username    string `json:"username,omitempty"`
				Password    string `json:"password,omitempty"` // this is also redacted
				Application string `json:"application,omitempty"`
			} `json:"credentials,omitempty"`
			Cookies []struct {
				HostKey    string `json:"host_key,omitempty"`
				Path       string `json:"path,omitempty"`
				ExpiresUtc string `json:"expires_utc,omitempty"`
				Name       string `json:"name,omitempty"`
				Value      string `json:"value,omitempty"`
			} `json:"cookies,omitempty"`
			UserInformation struct {
				IPAddress          string      `json:"ip_address,omitempty"`
				IPNetwork          interface{} `json:"ip_network,omitempty"`
				Username           string      `json:"username,omitempty"`
				CountryCode        string      `json:"country_code,omitempty"`
				ZipCode            string      `json:"zip_code,omitempty"`
				Location           string      `json:"location,omitempty"`
				Hwid               string      `json:"hwid,omitempty"`
				CurrentLanguage    string      `json:"current_language,omitempty"`
				ScreensizeWidth    int         `json:"screensize_width,omitempty"`
				ScreensizeHeight   int         `json:"screensize_height,omitempty"`
				Timezone           string      `json:"timezone,omitempty"`
				Os                 string      `json:"os,omitempty"`
				Uac                string      `json:"uac,omitempty"`
				ProcessElevation   interface{} `json:"process_elevation,omitempty"`
				AvailableKeyboards []string    `json:"available_keyboards,omitempty"`
				Hardware           []string    `json:"hardware,omitempty"`
				AntiViruses        interface{} `json:"anti_viruses,omitempty"`
			} `json:"user_information,omitempty"`
			MalwareInformation struct {
				MalwareFamily string    `json:"malware_family,omitempty"`
				BuildID       string    `json:"build_id,omitempty"`
				FileLocation  string    `json:"file_location,omitempty"`
				InfectionDate FlareTime `json:"infection_date,omitempty"`
			} `json:"malware_information,omitempty"`
			Files     []string    `json:"files,omitempty"`
			Resources []string    `json:"resources,omitempty"` // sometimes credentials are here in the format, "Host: URL  |  Username: EMAIL  |  Password: PASSWORD", But a lot of the time, the password value is redacted...
			Price     interface{} `json:"price,omitempty"`
			Currency  interface{} `json:"currency,omitempty"`
			Features  struct {
				Domains         []string    `json:"domains,omitempty"`
				Emails          []string    `json:"emails,omitempty"`
				IPAddresses     []string    `json:"ip_addresses,omitempty"`
				IPAddressesCidr []string    `json:"ip_addresses_cidr,omitempty"`
				ReversedDomains []string    `json:"reversed_domains,omitempty"`
				Urls            []string    `json:"urls,omitempty"`
				Usernames       []string    `json:"usernames,omitempty"`
				Vulnerabilities interface{} `json:"vulnerabilities,omitempty"`
			} `json:"features,omitempty"`
		} `json:"data,omitempty"`
		Duplicates []interface{} `json:"duplicates,omitempty"`
		Header     struct {
			Actor           interface{}   `json:"actor,omitempty"`
			Bank            interface{}   `json:"bank,omitempty"`
			Bin             interface{}   `json:"bin,omitempty"`
			Brand           interface{}   `json:"brand,omitempty"`
			CredentialCount int           `json:"credential_count,omitempty"`
			CategoryName    string        `json:"category_name,omitempty"`
			ContentHash     string        `json:"content_hash,omitempty"`
			ContentPreview  string        `json:"content_preview,omitempty"`
			Country         interface{}   `json:"country,omitempty"`
			Duplicates      []interface{} `json:"duplicates,omitempty"`
			EsScore         interface{}   `json:"es_score,omitempty"`
			Expiration      interface{}   `json:"expiration,omitempty"`
			Highlights      struct {
			} `json:"highlights,omitempty"`
			Host          interface{} `json:"host,omitempty"`
			ID            string      `json:"id,omitempty"`
			InfectionDate FlareTime   `json:"infection_date,omitempty"`
			ParentID      interface{} `json:"parent_id,omitempty"`
			ParentTitle   interface{} `json:"parent_title,omitempty"`
			ParentTitleEn interface{} `json:"parent_title_en,omitempty"`
			ParentUID     interface{} `json:"parent_uid,omitempty"`
			ParentUids    []string    `json:"parent_uids,omitempty"`
			Risk          struct {
				Score int `json:"score,omitempty"`
			} `json:"risk,omitempty"`
			SimilarItemsCount         int           `json:"similar_items_count,omitempty"`
			Source                    string        `json:"source,omitempty"`
			SourceName                string        `json:"source_name,omitempty"`
			TargetName                string        `json:"target_name,omitempty"`
			Tags                      []interface{} `json:"tags,omitempty"`
			Notes                     interface{}   `json:"notes,omitempty"`
			StateCode                 interface{}   `json:"state_code,omitempty"`
			Timestamp                 FlareTime     `json:"timestamp,omitempty"`
			Title                     string        `json:"title,omitempty"`
			Type                      string        `json:"type,omitempty"`
			UID                       string        `json:"uid,omitempty"`
			UserRiskScore             interface{}   `json:"user_risk_score,omitempty"`
			UserNotes                 interface{}   `json:"user_notes,omitempty"`
			IgnoredAt                 interface{}   `json:"ignored_at,omitempty"`
			RemediatedAt              interface{}   `json:"remediated_at,omitempty"`
			Verb                      string        `json:"verb,omitempty"`
			ExternalURL               string        `json:"external_url,omitempty"`
			ExternalNetloc            string        `json:"external_netloc,omitempty"`
			CanHaveDuplicates         bool          `json:"can_have_duplicates,omitempty"`
			PriorityActionUUIDRelated bool          `json:"priority_action_uuid_related,omitempty"`
			AnalyzersItemsUids        []interface{} `json:"analyzers_items_uids,omitempty"`
			VictimName                interface{}   `json:"victim_name,omitempty"`
		} `json:"header,omitempty"`
		HistoryLogs interface{} `json:"history_logs,omitempty"`
		Metadata    struct {
			EstimatedCreatedAt FlareTime   `json:"estimated_created_at,omitempty"`
			EventID            interface{} `json:"event_id,omitempty"`
			FirstCrawledAt     FlareTime   `json:"first_crawled_at,omitempty"`
			LastCrawledAt      FlareTime   `json:"last_crawled_at,omitempty"`
			PayloadDigest      string      `json:"payload_digest,omitempty"`
			ScrapedAt          FlareTime   `json:"scraped_at,omitempty"`
			Source             string      `json:"source,omitempty"`
			CrawledBy          interface{} `json:"crawled_by,omitempty"`
		} `json:"metadata,omitempty"`
		SimilarItems []interface{} `json:"similar_items,omitempty"`
	} `json:"activity,omitempty"`
}

// FlareStealerLogsCredential holds the parsed information for each entry
type FlareStealerLogsCredential struct {
	Software string
	URL      string
	Username string
	Password string
}

// Bulk Accounts Lookup Response Types

// FlareListByBulkAccountResponse structure to hold the API response
type FlareListByBulkAccountResponse map[string]Entry

// Entry represents each entry in the API response
type Entry struct {
	Links     map[string]interface{} `json:"links"`
	Name      string                 `json:"name"`
	Passwords []Password             `json:"passwords"`
}

// Password represents the details of a breached credential
type Password struct {
	CredentialHash string                 `json:"credential_hash"`
	Domain         *string                `json:"domain"` // Use *string to handle null values
	Extra          map[string]interface{} `json:"extra"`
	Hash           string                 `json:"hash"`
	HashType       string                 `json:"hash_type"`
	ID             int                    `json:"id"`
	ImportedAt     string                 `json:"imported_at"`
	Source         Source                 `json:"source"`
	SourceID       string                 `json:"source_id"`
	SourceParams   interface{}            `json:"source_params"`
}

// Source represents the breach source details
type Source struct {
	BreachedAt      string   `json:"breached_at"`
	Description     string   `json:"description"`
	DescriptionFR   string   `json:"description_fr"`
	HashDescription string   `json:"hash_description"`
	HashType        string   `json:"hash_type"`
	ID              string   `json:"id"`
	IsAlertsEnabled bool     `json:"is_alerts_enabled"`
	LeakedAt        string   `json:"leaked_at"`
	Name            string   `json:"name"`
	RelatedURLs     []string `json:"related_urls"`
	URL             *string  `json:"url"` // Use *string to handle null values
}

// Cookie ...
type Cookie struct {
	Domain         string
	Secure         bool
	Path           string
	HTTPOnly       bool
	Expiration     int64
	IsExpired      bool
	ExpirationDate string
	Name           string
	Value          string
}

// CookieBro ...
type CookieBro struct {
	Name             string      `json:"name,omitempty"`
	Value            string      `json:"value,omitempty"`
	Domain           string      `json:"domain,omitempty"`
	HostOnly         bool        `json:"hostOnly,omitempty"`
	Path             string      `json:"path,omitempty"`
	Secure           bool        `json:"secure,omitempty"`
	HTTPOnly         bool        `json:"httpOnly,omitempty"`
	SameSite         string      `json:"sameSite,omitempty"`
	Session          bool        `json:"session,omitempty"`
	FirstPartyDomain string      `json:"firstPartyDomain,omitempty"`
	PartitionKey     interface{} `json:"partitionKey,omitempty"`
	ExpirationDate   int64       `json:"expirationDate,omitempty"`
	StoreID          string      `json:"storeId,omitempty"`
}
