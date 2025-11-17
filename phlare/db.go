package phlare

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/projectdiscovery/gologger"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// InitializeBreachDatabase creates or opens the breach database for unredacted credentials storage
func InitializeBreachDatabase(company string) (*Database, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		gologger.Warning().Msgf("Could not get user homedir. Error: %+v\n", err)
	}
	// create database directory
	dbDir := fmt.Sprintf("%s/.config/gophlare/database", homeDir)
	if exists, err := utils.Exists(dbDir); !exists && err == nil {
		if err = os.MkdirAll(dbDir, 0750); err != nil {
			return nil, utils.LogError(err)
		}
	}
	sanitizedCompanyName := utils.SanitizeString(company)
	breachDBPath := fmt.Sprintf("%s/gophlare_%s_breach.sqlite3", dbDir, sanitizedCompanyName)
	conn, err := gorm.Open(sqlite.Open(breachDBPath+"?cache=shared&_pragma=foreign_keys(1)"), &gorm.Config{})
	if err != nil {
		return nil, utils.LogError(err)
	}
	if err = conn.AutoMigrate(
		&BreachCredential{},
		&FlareCredentialPairsDB{},
		&FlareCredentialASTP{},
		&StealerLog{},
		&StealerLogCredential{},
		&StealerLogCookie{},
		&StealerLogFile{},
		&StealerLogResource{},
		&StealerLogFeatureDomain{},
		&StealerLogFeatureEmail{},
		&StealerLogFeatureIP{},
		&StealerLogFeatureIPCidr{},
		&StealerLogFeatureReversedDomain{},
		&StealerLogFeatureUrl{},
		&StealerLogFeatureUsername{},
	); err != nil {
		return nil, utils.LogError(err)
	}
	return &Database{DB: conn, DBFilepath: breachDBPath}, nil
}

// InsertStealerLogActivities inserts FlareFireworkActivitiesIndexSourceIDv2Response data into the database in batches
//
//nolint:gocognit
func (db *Database) InsertStealerLogActivities(responses []FlareFireworkActivitiesIndexSourceIDv2Response, batchSize int) error {
	if batchSize <= 0 {
		batchSize = 100
	}

	if len(responses) == 0 {
		return nil
	}

	for _, response := range responses {
		activity := response.Activity

		// Convert interface{} fields to JSON strings
		esScoreJSON, _ := json.Marshal(activity.Data.EsScore)
		urlJSON, _ := json.Marshal(activity.Data.URL)
		browserURLJSON, _ := json.Marshal(activity.Data.BrowserURL)
		nameJSON, _ := json.Marshal(activity.Data.Name)
		sellerIDJSON, _ := json.Marshal(activity.Data.SellerID)
		ispJSON, _ := json.Marshal(activity.Data.Isp)
		informationJSON, _ := json.Marshal(activity.Data.Information)
		priceJSON, _ := json.Marshal(activity.Data.Price)
		currencyJSON, _ := json.Marshal(activity.Data.Currency)
		eventIDJSON, _ := json.Marshal(activity.Data.Metadata.EventID)
		crawledByJSON, _ := json.Marshal(activity.Data.Metadata.CrawledBy)
		ipNetworkJSON, _ := json.Marshal(activity.Data.UserInformation.IPNetwork)
		processElevationJSON, _ := json.Marshal(activity.Data.UserInformation.ProcessElevation)
		availableKeyboardsJSON, _ := json.Marshal(activity.Data.UserInformation.AvailableKeyboards)
		hardwareJSON, _ := json.Marshal(activity.Data.UserInformation.Hardware)
		antiVirusesJSON, _ := json.Marshal(activity.Data.UserInformation.AntiViruses)
		parentUidsJSON, _ := json.Marshal(activity.Header.ParentUids)
		tagsJSON, _ := json.Marshal(activity.Header.Tags)
		notesJSON, _ := json.Marshal(activity.Header.Notes)
		actorJSON, _ := json.Marshal(activity.Header.Actor)
		bankJSON, _ := json.Marshal(activity.Header.Bank)
		binJSON, _ := json.Marshal(activity.Header.Bin)
		brandJSON, _ := json.Marshal(activity.Header.Brand)
		countryJSON, _ := json.Marshal(activity.Header.Country)
		headerEsScoreJSON, _ := json.Marshal(activity.Header.EsScore)
		expirationJSON, _ := json.Marshal(activity.Header.Expiration)
		hostJSON, _ := json.Marshal(activity.Header.Host)
		parentIDJSON, _ := json.Marshal(activity.Header.ParentID)
		parentTitleJSON, _ := json.Marshal(activity.Header.ParentTitle)
		parentTitleEnJSON, _ := json.Marshal(activity.Header.ParentTitleEn)
		parentUIDJSON, _ := json.Marshal(activity.Header.ParentUID)
		stateCodeJSON, _ := json.Marshal(activity.Header.StateCode)
		userRiskScoreJSON, _ := json.Marshal(activity.Header.UserRiskScore)
		userNotesJSON, _ := json.Marshal(activity.Header.UserNotes)
		ignoredAtJSON, _ := json.Marshal(activity.Header.IgnoredAt)
		remediatedAtJSON, _ := json.Marshal(activity.Header.RemediatedAt)
		analyzersItemsUidsJSON, _ := json.Marshal(activity.Header.AnalyzersItemsUids)
		victimNameJSON, _ := json.Marshal(activity.Header.VictimName)
		historyLogsJSON, _ := json.Marshal(activity.HistoryLogs)

		// Helper function to convert FlareTime to *time.Time
		convertFlareTime := func(ft FlareTime) *time.Time {
			if ft.IsZero() {
				return nil
			}
			t := ft.Time
			return &t
		}

		// Create StealerLog record
		stealerLog := StealerLog{
			EsID:        activity.Data.EsID,
			EsScore:     string(esScoreJSON),
			ApiID:       activity.Data.ID,
			Index:       activity.Data.Index,
			UID:         activity.Data.UID,
			URL:         string(urlJSON),
			BrowserURL:  string(browserURLJSON),
			Name:        string(nameJSON),
			InstalledAt: convertFlareTime(activity.Data.InstalledAt),
			UpdatedAt:   nil, // using gorm.Model's UpdatedAt instead
			SellerID:    string(sellerIDJSON),
			Isp:         string(ispJSON),
			Information: string(informationJSON),
			Price:       string(priceJSON),
			Currency:    string(currencyJSON),

			EstimatedCreatedAt: convertFlareTime(activity.Data.Metadata.EstimatedCreatedAt),
			EventID:            string(eventIDJSON),
			FirstCrawledAt:     convertFlareTime(activity.Data.Metadata.FirstCrawledAt),
			LastCrawledAt:      convertFlareTime(activity.Data.Metadata.LastCrawledAt),
			PayloadDigest:      activity.Data.Metadata.PayloadDigest,
			ScrapedAt:          convertFlareTime(activity.Data.Metadata.ScrapedAt),
			Source:             activity.Data.Metadata.Source,
			CrawledBy:          string(crawledByJSON),

			IPAddress:          activity.Data.UserInformation.IPAddress,
			IPNetwork:          string(ipNetworkJSON),
			Username:           activity.Data.UserInformation.Username,
			CountryCode:        activity.Data.UserInformation.CountryCode,
			ZipCode:            activity.Data.UserInformation.ZipCode,
			Location:           activity.Data.UserInformation.Location,
			Hwid:               activity.Data.UserInformation.Hwid,
			CurrentLanguage:    activity.Data.UserInformation.CurrentLanguage,
			ScreensizeWidth:    activity.Data.UserInformation.ScreensizeWidth,
			ScreensizeHeight:   activity.Data.UserInformation.ScreensizeHeight,
			Timezone:           activity.Data.UserInformation.Timezone,
			Os:                 activity.Data.UserInformation.Os,
			Uac:                activity.Data.UserInformation.Uac,
			ProcessElevation:   string(processElevationJSON),
			AvailableKeyboards: string(availableKeyboardsJSON),
			Hardware:           string(hardwareJSON),
			AntiViruses:        string(antiVirusesJSON),

			MalwareFamily: activity.Data.MalwareInformation.MalwareFamily,
			BuildID:       activity.Data.MalwareInformation.BuildID,
			FileLocation:  activity.Data.MalwareInformation.FileLocation,
			InfectionDate: convertFlareTime(activity.Data.MalwareInformation.InfectionDate),

			Actor:                     string(actorJSON),
			Bank:                      string(bankJSON),
			Bin:                       string(binJSON),
			Brand:                     string(brandJSON),
			CredentialCount:           activity.Header.CredentialCount,
			CategoryName:              activity.Header.CategoryName,
			ContentHash:               activity.Header.ContentHash,
			ContentPreview:            activity.Header.ContentPreview,
			Country:                   string(countryJSON),
			HeaderEsScore:             string(headerEsScoreJSON),
			Expiration:                string(expirationJSON),
			Host:                      string(hostJSON),
			HeaderID:                  activity.Header.ID,
			HeaderInfectionDate:       convertFlareTime(activity.Header.InfectionDate),
			ParentID:                  string(parentIDJSON),
			ParentTitle:               string(parentTitleJSON),
			ParentTitleEn:             string(parentTitleEnJSON),
			ParentUID:                 string(parentUIDJSON),
			ParentUids:                string(parentUidsJSON),
			RiskScore:                 activity.Header.Risk.Score,
			SimilarItemsCount:         activity.Header.SimilarItemsCount,
			SourceName:                activity.Header.SourceName,
			TargetName:                activity.Header.TargetName,
			Tags:                      string(tagsJSON),
			Notes:                     string(notesJSON),
			StateCode:                 string(stateCodeJSON),
			Timestamp:                 convertFlareTime(activity.Header.Timestamp),
			Title:                     activity.Header.Title,
			Type:                      activity.Header.Type,
			HeaderUID:                 activity.Header.UID,
			UserRiskScore:             string(userRiskScoreJSON),
			UserNotes:                 string(userNotesJSON),
			IgnoredAt:                 string(ignoredAtJSON),
			RemediatedAt:              string(remediatedAtJSON),
			Verb:                      activity.Header.Verb,
			ExternalURL:               activity.Header.ExternalURL,
			ExternalNetloc:            activity.Header.ExternalNetloc,
			CanHaveDuplicates:         activity.Header.CanHaveDuplicates,
			PriorityActionUUIDRelated: activity.Header.PriorityActionUUIDRelated,
			AnalyzersItemsUids:        string(analyzersItemsUidsJSON),
			VictimName:                string(victimNameJSON),
			HistoryLogs:               string(historyLogsJSON),
		}

		// Insert main record with upsert on UID conflict
		if err := db.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "uid"}},
			DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
		}).Create(&stealerLog).Error; err != nil {
			gologger.Warning().Msgf("Failed to insert stealer log %s: %v", stealerLog.UID, err)
			continue
		}

		// Insert credentials in batches
		if len(activity.Data.Credentials) > 0 {
			credentials := make([]StealerLogCredential, 0, len(activity.Data.Credentials))
			for _, cred := range activity.Data.Credentials {
				credentials = append(credentials, StealerLogCredential{
					StealerLogID: stealerLog.ID,
					URL:          cred.URL,
					Username:     cred.Username,
					Password:     cred.Password,
					Application:  cred.Application,
				})
			}
			if err := db.CreateInBatches(credentials, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert credentials for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert cookies in batches
		if len(activity.Data.Cookies) > 0 {
			cookies := make([]StealerLogCookie, 0, len(activity.Data.Cookies))
			for _, cookie := range activity.Data.Cookies {
				cookies = append(cookies, StealerLogCookie{
					StealerLogID: stealerLog.ID,
					HostKey:      cookie.HostKey,
					Path:         cookie.Path,
					ExpiresUtc:   cookie.ExpiresUtc,
					Name:         cookie.Name,
					Value:        cookie.Value,
				})
			}
			if err := db.CreateInBatches(cookies, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert cookies for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert files in batches
		if len(activity.Data.Files) > 0 {
			files := make([]StealerLogFile, 0, len(activity.Data.Files))
			for _, file := range activity.Data.Files {
				files = append(files, StealerLogFile{
					StealerLogID: stealerLog.ID,
					FilePath:     file,
				})
			}
			if err := db.CreateInBatches(files, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert files for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert resources in batches
		if len(activity.Data.Resources) > 0 {
			resources := make([]StealerLogResource, 0, len(activity.Data.Resources))
			for _, resource := range activity.Data.Resources {
				resources = append(resources, StealerLogResource{
					StealerLogID: stealerLog.ID,
					Resource:     resource,
				})
			}
			if err := db.CreateInBatches(resources, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert resources for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert feature domains in batches
		if len(activity.Data.Features.Domains) > 0 {
			domains := make([]StealerLogFeatureDomain, 0, len(activity.Data.Features.Domains))
			for _, domain := range activity.Data.Features.Domains {
				domains = append(domains, StealerLogFeatureDomain{
					StealerLogID: stealerLog.ID,
					Domain:       domain,
				})
			}
			if err := db.CreateInBatches(domains, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert feature domains for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert feature emails in batches
		if len(activity.Data.Features.Emails) > 0 {
			emails := make([]StealerLogFeatureEmail, 0, len(activity.Data.Features.Emails))
			for _, email := range activity.Data.Features.Emails {
				emails = append(emails, StealerLogFeatureEmail{
					StealerLogID: stealerLog.ID,
					Email:        email,
				})
			}
			if err := db.CreateInBatches(emails, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert feature emails for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert feature IP addresses in batches
		if len(activity.Data.Features.IPAddresses) > 0 {
			ips := make([]StealerLogFeatureIP, 0, len(activity.Data.Features.IPAddresses))
			for _, ip := range activity.Data.Features.IPAddresses {
				ips = append(ips, StealerLogFeatureIP{
					StealerLogID: stealerLog.ID,
					IPAddress:    ip,
				})
			}
			if err := db.CreateInBatches(ips, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert feature IPs for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert feature CIDR IP addresses in batches
		if len(activity.Data.Features.IPAddressesCidr) > 0 {
			cidrs := make([]StealerLogFeatureIPCidr, 0, len(activity.Data.Features.IPAddressesCidr))
			for _, cidr := range activity.Data.Features.IPAddressesCidr {
				cidrs = append(cidrs, StealerLogFeatureIPCidr{
					StealerLogID: stealerLog.ID,
					IPCidr:       cidr,
				})
			}
			if err := db.CreateInBatches(cidrs, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert feature CIDR IPs for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert feature reversed domains in batches
		if len(activity.Data.Features.ReversedDomains) > 0 {
			reversedDomains := make([]StealerLogFeatureReversedDomain, 0, len(activity.Data.Features.ReversedDomains))
			for _, rd := range activity.Data.Features.ReversedDomains {
				reversedDomains = append(reversedDomains, StealerLogFeatureReversedDomain{
					StealerLogID:   stealerLog.ID,
					ReversedDomain: rd,
				})
			}
			if err := db.CreateInBatches(reversedDomains, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert feature reversed domains for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert feature URLs in batches
		if len(activity.Data.Features.Urls) > 0 {
			urls := make([]StealerLogFeatureUrl, 0, len(activity.Data.Features.Urls))
			for _, url := range activity.Data.Features.Urls {
				urls = append(urls, StealerLogFeatureUrl{
					StealerLogID: stealerLog.ID,
					URL:          url,
				})
			}
			if err := db.CreateInBatches(urls, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert feature URLs for stealer log %s: %v", stealerLog.UID, err)
			}
		}

		// Insert feature usernames in batches
		if len(activity.Data.Features.Usernames) > 0 {
			usernames := make([]StealerLogFeatureUsername, 0, len(activity.Data.Features.Usernames))
			for _, username := range activity.Data.Features.Usernames {
				usernames = append(usernames, StealerLogFeatureUsername{
					StealerLogID: stealerLog.ID,
					Username:     username,
				})
			}
			if err := db.CreateInBatches(usernames, batchSize).Error; err != nil {
				gologger.Warning().Msgf("Failed to insert feature usernames for stealer log %s: %v", stealerLog.UID, err)
			}
		}
	}

	return nil
}

// InsertFlareStealerLogsCredentials inserts FlareStealerLogsCredential data into the BreachCredential table in batches
func (db *Database) InsertFlareStealerLogsCredentials(credentials []FlareStealerLogsCredential, source string, batchSize int, domain string, inScope bool) error {
	if batchSize <= 0 {
		batchSize = 100
	}

	if credentials == nil {
		return nil
	}

	breachCredentials := make([]BreachCredential, 0, len(credentials))
	for _, cred := range credentials {
		breachCredentials = append(breachCredentials, BreachCredential{
			Username: cred.Username,
			Password: cred.Password,
			Source:   source,
			URL:      cred.URL,
			InScope:  inScope,
			Domain:   domain,
		})
	}

	if len(breachCredentials) > 0 {
		if err := db.CreateInBatches(breachCredentials, batchSize).Error; err != nil {
			return utils.LogError(err)
		}
	}

	return nil
}

// FlareCredentialPairInput represents input data for inserting Flare credential pairs
type FlareCredentialPairInput struct {
	Email      string
	Password   string
	Hash       string
	SourceID   string
	Domain     string
	ImportedAt time.Time
	LeakedAt   interface{} // can be time.Time, string, or nil
	BreachedAt interface{} // can be time.Time, string, or nil
}

// InsertFlareCredentialPairs inserts Flare credential pair data into the FlareCredentialPairsDB table in batches
//
//nolint:gocognit
func (db *Database) InsertFlareCredentialPairs(credentialData []FlareCredentialPairInput, batchSize int) error {
	if batchSize <= 0 {
		batchSize = 100
	}

	if len(credentialData) == 0 {
		gologger.Info().Msg("No Flare credential pairs to insert")
		return nil
	}

	credentials := make([]FlareCredentialPairsDB, 0, len(credentialData))
	for _, cred := range credentialData {
		dbCred := FlareCredentialPairsDB{
			Email:    cred.Email,
			Password: cred.Password,
			Hash:     cred.Hash,
			SourceID: cred.SourceID,
			Domain:   cred.Domain,
		}

		// Handle ImportedAt
		if !cred.ImportedAt.IsZero() {
			importedAt := cred.ImportedAt
			dbCred.ImportedAt = &importedAt
		}

		// Handle LeakedAt (can be time.Time or string or nil)
		if cred.LeakedAt != nil {
			switch v := cred.LeakedAt.(type) {
			case time.Time:
				if !v.IsZero() {
					dbCred.LeakedAt = &v
				}
			case string:
				if v != "" {
					if parsed, err := time.Parse(time.RFC3339, v); err == nil {
						dbCred.LeakedAt = &parsed
					}
				}
			}
		}

		// Handle BreachedAt (can be time.Time or string or nil)
		if cred.BreachedAt != nil {
			switch v := cred.BreachedAt.(type) {
			case time.Time:
				if !v.IsZero() {
					dbCred.BreachedAt = &v
				}
			case string:
				if v != "" {
					if parsed, err := time.Parse(time.RFC3339, v); err == nil {
						dbCred.BreachedAt = &parsed
					}
				}
			}
		}

		credentials = append(credentials, dbCred)
	}

	if len(credentials) > 0 {
		if err := db.CreateInBatches(credentials, batchSize).Error; err != nil {
			gologger.Error().Msgf("Failed to insert Flare credential pairs: %v", err)
			return utils.LogError(err)
		}
		gologger.Info().Msgf("Successfully inserted %d Flare credential pairs", len(credentials))
	}

	return nil
}

// InsertFlareCredentialsASTP inserts FlareSearchCredentialsASTP data into the FlareCredentialASTP table in batches
//
//nolint:gocognit
func (db *Database) InsertFlareCredentialsASTP(data *FlareSearchCredentialsASTP, batchSize int) error {
	if batchSize <= 0 {
		batchSize = 100
	}

	if data == nil || len(data.Items) == 0 {
		gologger.Info().Msg("No Flare ASTP credentials to insert")
		return nil
	}

	credentials := make([]FlareCredentialASTP, 0, len(data.Items))
	for _, item := range data.Items {
		dbCred := FlareCredentialASTP{
			FlareID:      item.ID,
			Domain:       item.Domain,
			Hash:         item.Hash,
			IdentityName: item.IdentityName,
			SourceID:     item.SourceID,
		}

		// Handle HashType (interface{} to string)
		if item.HashType != nil {
			if hashType, ok := item.HashType.(string); ok {
				dbCred.HashType = hashType
			}
		}

		// Handle KnownPasswordID (interface{} to string)
		if item.KnownPasswordID != nil {
			switch v := item.KnownPasswordID.(type) {
			case string:
				dbCred.KnownPasswordID = v
			case int64:
				dbCred.KnownPasswordID = fmt.Sprintf("%d", v)
			case float64:
				dbCred.KnownPasswordID = fmt.Sprintf("%.0f", v)
			}
		}

		// Handle ImportedAt
		if !item.ImportedAt.IsZero() {
			importedAt := item.ImportedAt
			dbCred.ImportedAt = &importedAt
		}

		// Handle Source fields
		dbCred.SourceName = item.Source.Name
		dbCred.SourceDescriptionEn = item.Source.DescriptionEn
		dbCred.SourceDescriptionFr = item.Source.DescriptionFr
		dbCred.IsAlertEnabled = item.Source.IsAlertEnabled

		// Handle SourceBreachedAt (interface{} that can be time.Time or string)
		if item.Source.BreachedAt != nil {
			switch v := item.Source.BreachedAt.(type) {
			case time.Time:
				if !v.IsZero() {
					dbCred.SourceBreachedAt = &v
				}
			case string:
				if v != "" {
					if parsed, err := time.Parse(time.RFC3339, v); err == nil {
						dbCred.SourceBreachedAt = &parsed
					}
				}
			}
		}

		// Handle SourceLeakedAt (interface{} that can be time.Time or string)
		if item.Source.LeakedAt != nil {
			switch v := item.Source.LeakedAt.(type) {
			case time.Time:
				if !v.IsZero() {
					dbCred.SourceLeakedAt = &v
				}
			case string:
				if v != "" {
					if parsed, err := time.Parse(time.RFC3339, v); err == nil {
						dbCred.SourceLeakedAt = &parsed
					}
				}
			}
		}

		credentials = append(credentials, dbCred)
	}

	if len(credentials) > 0 {
		if err := db.CreateInBatches(credentials, batchSize).Error; err != nil {
			gologger.Error().Msgf("Failed to insert Flare ASTP credentials: %v", err)
			return utils.LogError(err)
		}
		gologger.Info().Msgf("Successfully inserted %d Flare ASTP credentials", len(credentials))
	}

	return nil
}

// CopyBreachDBToOutputDir ...
func (db *Database) CopyBreachDBToOutputDir(outputDir string) error {
	dbFileName := filepath.Base(db.DBFilepath)
	dest := fmt.Sprintf("%s/%s.gz", outputDir, dbFileName)
	if exists, err := utils.Exists(db.DBFilepath); exists && err == nil {
		if err = utils.GzipCompressFile(db.DBFilepath, dest); err != nil {
			return utils.LogError(err)
		}
	}

	return nil
}
