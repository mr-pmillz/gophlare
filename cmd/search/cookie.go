package search

import (
	"bufio"
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/mr-pmillz/gophlare/utils"
	"os"
	"strconv"
	"strings"
	"time"
)

// FindHighValueCookies filters and returns cookies considered high value based on predefined provider-specific criteria.
// It identifies cookies from a list that match names or prefixes associated with specific providers' authentication tokens.
func FindHighValueCookies(cookies []phlare.Cookie) []phlare.Cookie {
	// Define a map to group cookies by their respective providers
	cookieMap := map[string][]string{
		"Microsoft": {
			"ESTSAUTH",                    // Contains user's session information for SSO (transient).
			"ESTSAUTHPERSISTENT",          // Persistent session token for SSO across Microsoft services.
			"ESTSAUTHLIGHT",               // Stores session GUID information, often used in lightweight authentication flows.
			"ESTSAUTHPERSISTENTLIGHT",     // A lightweight version of ESTSAUTHPERSISTENT, often used in hybrid authentication scenarios.
			"x-ms-refreshtokencredential", // Used when Primary Refresh Token (PRT) is active to maintain session state.
			"SSOCOOKIE",                   // Secure authentication cookie enabling seamless SSO across Microsoft services.
			"MSCC",                        // Microsoft account consent cookie, storing user preferences for authentication prompts.
			"MUID",                        // Machine-unique identifier used for tracking authentication and security checks.
			"MSPAuth",                     // Authentication token for Microsoft Account services, used in login sessions.
			"MSPProf",                     // Stores user profile-related authentication data.
			"MSPOK",                       // Helps confirm successful authentication for Microsoft services.
			"RPSAuth",                     // Main authentication token for maintaining session state.
			"RPSSecAuth",                  // Secure authentication token for Microsoft Entra ID and 365 services.
			"MS0",                         // Session management cookie used for authentication and maintaining login state.
			"MSFPC",                       // Used for tracking and authentication across Microsoft services.
			"MSAAuth",                     // Authentication token for Microsoft Account sign-ins.
			"MSAAUTHP",                    // Persistent authentication cookie for Microsoft 365 services.
			"WT_FPC",                      // First-party authentication tracking cookie used for session persistence.
			"MSAToken",                    // Stores a user's token for authentication and access control.
			"FPC",                         // Microsoft’s first-party cookie used for authentication and tracking logged-in sessions.
			"PPAuth",                      // Microsoft Passport authentication token for secure sign-ins.
		},
		"Azure": {
			"x-ms-cpim-trans", // Used for tracking authentication requests and current transactions.
			"x-ms-cpim-sso",   // {Id}: Used for maintaining the SSO session.
			"x-ms-cpim-cache", // {id}_n: Used for maintaining the request state.
			"x-ms-cpim-rp",    // Stores relying party information in federated authentication scenarios.
			"x-ms-cpim-rc",    // Stores the user's authentication state across multiple requests.
			"AzureADAuth",     // Authentication token used specifically in Microsoft Entra ID (Azure AD).
		},
		"Microsoft 365": {
			"OfficeAuth",       // Authentication token for Microsoft 365 applications like Outlook and Teams.
			"AdminConsoleAuth", // Authentication token used for Microsoft Admin Console and Azure Portal access.
		},
		"Microsoft Admin Console": {
			"IDCAuth", // Identity authentication cookie used in Microsoft Admin portals.
			"CtxAuth", // Contextual authentication token for Microsoft Admin and Entra ID portals.
		},
		"SharePoint": {
			"FedAuth", // FedAuth: Used for each top-level site in SharePoint
			"rtFA",    //		rtFA: Used across all of SharePoint for silent authentication
		},
		"Google": {
			"SID",               // Primary session ID cookie, used for authentication and security, lasts for 2 years.
			"HSID",              // Secure cookie containing encrypted user account information, helps prevent fraudulent logins.
			"SSID",              // Used for authentication, security, and session management across Google services.
			"APISID",            // Stores user authentication data for persistent login across Google services.
			"SAPISID",           // Similar to APISID, used for authentication and enforcing security policies.
			"SIDCC",             // Security cookie protecting against unauthorized access and account hijacking.
			"NID",               // Stores user preferences and login-related information, often used in Google search.
			"G_AUTHUSER_H",      // Identifies the signed-in user when multiple accounts are used.
			"GAPS",              // Session management cookie used for login authentication.
			"__Secure-1PSID",    // First-party session ID for authentication and security within Google services.
			"__Secure-3PSID",    // Third-party session ID for authentication across Google's services and third-party sites.
			"__Secure-1PAPISID", // First-party authentication token used for persistent login and security.
			"__Secure-3PAPISID", // Third-party authentication token for maintaining authentication across Google services.
			"__Secure-YEC",      // Security-related cookie, used to enhance authentication and session integrity.
		},
	}

	// fmt.Println("Cookie Map:", cookieMap)
	var highValueCookies []phlare.Cookie
	for _, cookie := range cookies {
		for provider, prefixes := range cookieMap {
			for _, prefix := range prefixes {
				if strings.HasPrefix(cookie.Name, prefix) {
					// if verbose print. TODO: include opts.Verbose
					utils.InfoLabelWithColorf("Live Cookie", "yellow", "Cookie %s matches prefix %s for provider: %s", cookie.Name, prefix, provider)
					highValueCookies = append(highValueCookies, cookie)
					break
				}
			}
		}
	}
	utils.InfoLabelWithColorf("Live Cookies", "green", "Found %d live high value cookies", len(highValueCookies))
	return highValueCookies
}

// ParseCookieFile parses a cookies file and returns only the high value live cookies and an error
func ParseCookieFile(filename string) ([]phlare.Cookie, []phlare.Cookie, error) {
	utils.InfoLabelWithColorf("FLARE STEALER LOGS", "cyan", "Parsing %s for live cookies", filename)
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var cookies []phlare.Cookie

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024) // Increase the buffer size to handle large lines
	scanner.Buffer(buf, 1024*1024)  // Set the maximum token size to 1MB

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 7 {
			continue // Skip malformed lines
		}

		secure, err := strconv.ParseBool(strings.ToLower(fields[1])) // ToDo: Double check if this is indeed the secure cookie boolean
		if err != nil {
			continue
		}
		httpOnly, err := strconv.ParseBool(strings.ToLower(fields[3])) // ToDo: Double check if this is indeed the HTTPOnly cookie boolean
		if err != nil {
			continue
		}
		expiration, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			continue
		}

		cookies = append(cookies, phlare.Cookie{
			Domain:     fields[0],
			Secure:     secure,
			Path:       fields[2],
			HTTPOnly:   httpOnly,
			Expiration: expiration,
			Name:       fields[5],
			Value:      fields[6],
		})
	}

	if err = scanner.Err(); err != nil {
		return nil, nil, err
	}

	liveCookies, err := CheckCookieExpiration(cookies)
	if err != nil {
		return nil, nil, utils.LogError(err)
	}

	// check live cookies for high value targets
	highValueCookies := FindHighValueCookies(liveCookies)

	return liveCookies, highValueCookies, nil
}

// MapCookiesToCookieBro converts a slice of Cookie structs into a slice of CookieBro structs with adjusted fields.
func MapCookiesToCookieBro(cookies []phlare.Cookie) []phlare.CookieBro {
	cookieBros := make([]phlare.CookieBro, 0)
	for _, cookie := range cookies {
		cookieBros = append(cookieBros, phlare.CookieBro{
			Name:           cookie.Name,
			Value:          cookie.Value,
			Domain:         cookie.Domain,
			Path:           cookie.Path,
			Secure:         cookie.Secure,
			HTTPOnly:       cookie.HTTPOnly,
			ExpirationDate: int(cookie.Expiration),
		})
	}

	return cookieBros
}

// CheckCookieExpiration filters out expired cookies from the provided slice and returns live cookies or an error if any.
func CheckCookieExpiration(cookies []phlare.Cookie) ([]phlare.Cookie, error) {
	liveCookies := make([]phlare.Cookie, 0)
	for _, cookie := range cookies {
		isExpired, _ := CheckExpirationRFC3339(cookie.Expiration)
		if !isExpired {
			// utils.InfoLabelWithColorf("Cookie", "green", "Cookie %s is not expired until %s", cookie.Name, expirationDate)
			liveCookies = append(liveCookies, cookie)
		}
	}
	return liveCookies, nil
}

// CheckExpirationRFC3339 checks if a given epoch timestamp is expired and returns:
// - A bool indicating whether it's expired
// - A string representing the expiration time in RFC3339 format
func CheckExpirationRFC3339(epochTimestamp int64) (bool, string) {
	expirationTime := time.Unix(epochTimestamp, 0).UTC()
	expired := time.Now().After(expirationTime)
	return expired, expirationTime.Format(time.RFC3339)
}
