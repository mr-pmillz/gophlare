package phlare

import (
	"time"

	"gorm.io/gorm"
)

// Database is a wrapper around *gorm.DB
type Database struct {
	*gorm.DB
	DBFilepath string
}

// BreachCredential ...
type BreachCredential struct {
	gorm.Model
	Username string `gorm:"index"`
	Password string `gorm:"type:text"`
	Source   string
	URL      string `gorm:"type:text"`
	InScope  bool   `gorm:"index"`
	Domain   string `gorm:"index"`
}

// FlareCredentialPairsDB ...
type FlareCredentialPairsDB struct {
	gorm.Model
	Email      string
	Password   string
	Hash       string
	SourceID   string
	Domain     string
	ImportedAt *time.Time
	LeakedAt   *time.Time
	BreachedAt *time.Time
}

// StealerLog represents the main activity/stealer log entry
type StealerLog struct {
	gorm.Model
	// Data fields
	EsID        string `gorm:"index"`
	EsScore     string `gorm:"type:text"` // stored as JSON string
	ApiID       string `gorm:"index"`     // API's ID field (renamed to avoid conflict with gorm.Model.ID)
	Index       string
	UID         string `gorm:"uniqueIndex"`
	URL         string `gorm:"type:text"`
	BrowserURL  string `gorm:"type:text"`
	Name        string
	InstalledAt *time.Time
	UpdatedAt   *time.Time
	SellerID    string
	Isp         string `gorm:"type:text"`
	Information string `gorm:"type:text"` // stored as JSON string
	Price       string
	Currency    string

	// Metadata
	EstimatedCreatedAt *time.Time `gorm:"index"`
	EventID            string
	FirstCrawledAt     *time.Time
	LastCrawledAt      *time.Time
	PayloadDigest      string `gorm:"index"`
	ScrapedAt          *time.Time
	Source             string `gorm:"index"`
	CrawledBy          string

	// User Information
	IPAddress          string `gorm:"index"`
	IPNetwork          string
	Username           string `gorm:"index"`
	CountryCode        string `gorm:"index"`
	ZipCode            string
	Location           string
	Hwid               string `gorm:"index"`
	CurrentLanguage    string
	ScreensizeWidth    int
	ScreensizeHeight   int
	Timezone           string
	Os                 string `gorm:"index"`
	Uac                string
	ProcessElevation   string
	AvailableKeyboards string `gorm:"type:text"` // stored as JSON string
	Hardware           string `gorm:"type:text"` // stored as JSON string
	AntiViruses        string `gorm:"type:text"` // stored as JSON string

	// Malware Information
	MalwareFamily string `gorm:"index"`
	BuildID       string
	FileLocation  string
	InfectionDate *time.Time `gorm:"index"`

	// Header fields
	Actor                     string `gorm:"type:text"`
	Bank                      string
	Bin                       string
	Brand                     string
	CredentialCount           int
	CategoryName              string `gorm:"index"`
	ContentHash               string `gorm:"index"`
	ContentPreview            string `gorm:"type:text"`
	Country                   string
	HeaderEsScore             string
	Expiration                string
	Host                      string
	HeaderID                  string
	HeaderInfectionDate       *time.Time
	ParentID                  string
	ParentTitle               string
	ParentTitleEn             string
	ParentUID                 string
	ParentUids                string `gorm:"type:text"` // stored as JSON string
	RiskScore                 int
	SimilarItemsCount         int
	SourceName                string `gorm:"index"`
	TargetName                string `gorm:"index"`
	Tags                      string `gorm:"type:text"` // stored as JSON string
	Notes                     string `gorm:"type:text"`
	StateCode                 string
	Timestamp                 *time.Time `gorm:"index"`
	Title                     string
	Type                      string `gorm:"index"`
	HeaderUID                 string
	UserRiskScore             string
	UserNotes                 string `gorm:"type:text"`
	IgnoredAt                 string
	RemediatedAt              string
	Verb                      string
	ExternalURL               string `gorm:"type:text"`
	ExternalNetloc            string
	CanHaveDuplicates         bool
	PriorityActionUUIDRelated bool
	AnalyzersItemsUids        string `gorm:"type:text"` // stored as JSON string
	VictimName                string

	// History Logs
	HistoryLogs string `gorm:"type:text"` // stored as JSON string

	// Relationships
	Credentials            []StealerLogCredential            `gorm:"foreignKey:StealerLogID"`
	Cookies                []StealerLogCookie                `gorm:"foreignKey:StealerLogID"`
	Files                  []StealerLogFile                  `gorm:"foreignKey:StealerLogID"`
	Resources              []StealerLogResource              `gorm:"foreignKey:StealerLogID"`
	FeatureDomains         []StealerLogFeatureDomain         `gorm:"foreignKey:StealerLogID"`
	FeatureEmails          []StealerLogFeatureEmail          `gorm:"foreignKey:StealerLogID"`
	FeatureIPs             []StealerLogFeatureIP             `gorm:"foreignKey:StealerLogID"`
	FeatureIPsCidr         []StealerLogFeatureIPCidr         `gorm:"foreignKey:StealerLogID"`
	FeatureReversedDomains []StealerLogFeatureReversedDomain `gorm:"foreignKey:StealerLogID"`
	FeatureUrls            []StealerLogFeatureUrl            `gorm:"foreignKey:StealerLogID"`
	FeatureUsernames       []StealerLogFeatureUsername       `gorm:"foreignKey:StealerLogID"`
}

// StealerLogCredential represents credentials found in stealer logs
type StealerLogCredential struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	URL          string `gorm:"type:text;index"`
	Username     string `gorm:"index"`
	Password     string `gorm:"type:text"`
	Application  string `gorm:"index"`
}

// StealerLogCookie represents cookies found in stealer logs
type StealerLogCookie struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	HostKey      string `gorm:"index"`
	Path         string
	ExpiresUtc   string
	Name         string `gorm:"index"`
	Value        string `gorm:"type:text"`
}

// StealerLogFile represents files found in stealer logs
type StealerLogFile struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	FilePath     string `gorm:"type:text"`
}

// StealerLogResource represents resources found in stealer logs
type StealerLogResource struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	Resource     string `gorm:"type:text"`
}

// StealerLogFeatureDomain represents domains in features
type StealerLogFeatureDomain struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	Domain       string `gorm:"index"`
}

// StealerLogFeatureEmail represents emails in features
type StealerLogFeatureEmail struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	Email        string `gorm:"index"`
}

// StealerLogFeatureIP represents IP addresses in features
type StealerLogFeatureIP struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	IPAddress    string `gorm:"index"`
}

// StealerLogFeatureIPCidr represents CIDR IP addresses in features
type StealerLogFeatureIPCidr struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	IPCidr       string `gorm:"index"`
}

// StealerLogFeatureReversedDomain represents reversed domains in features
type StealerLogFeatureReversedDomain struct {
	gorm.Model
	StealerLogID   uint   `gorm:"index"`
	ReversedDomain string `gorm:"index"`
}

// StealerLogFeatureUrl represents URLs in features
type StealerLogFeatureUrl struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	URL          string `gorm:"type:text;index"`
}

// StealerLogFeatureUsername represents usernames in features
type StealerLogFeatureUsername struct {
	gorm.Model
	StealerLogID uint   `gorm:"index"`
	Username     string `gorm:"index"`
}
