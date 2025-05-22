package bloodhound

import (
	"context"
	"encoding/json"
	"fmt"
	bhsdk "github.com/SpecterOps/bloodhound-go-sdk/sdk"
	"github.com/mr-pmillz/gophlare/phlare"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
)

// BHCEClient ...
type BHCEClient struct {
	Client *bhsdk.ClientWithResponses
}

// BHCELoginResponse ...
type BHCELoginResponse struct {
	Data struct {
		UserID       string `json:"user_id,omitempty"`
		AuthExpired  bool   `json:"auth_expired,omitempty"`
		SessionToken string `json:"session_token,omitempty"`
	} `json:"data,omitempty"`
}

// BHCEAPIOptions ...
type BHCEAPIOptions struct {
	ServerURL string
	User      string
	Password  string
}

// NewBloodHoundAPIOptions ...
func NewBloodHoundAPIOptions(serverURL, user, password string) *BHCEAPIOptions {
	return &BHCEAPIOptions{
		ServerURL: serverURL,
		User:      user,
		Password:  password,
	}
}

// NewBloodHoundAPIClient authenticates to Bloodhound CE Web app and returns a bloodhound.ClientWithResponses object using the session token.
func NewBloodHoundAPIClient(bhceAPIOpts *BHCEAPIOptions) (*BHCEClient, error) {
	c := phlare.NewHTTPClientWithTimeOut(true, 300)
	bloodhoundGetBearerTokenURL := fmt.Sprintf("%s/api/v2/login", bhceAPIOpts.ServerURL)
	requestBody, err := json.Marshal(map[string]string{
		"login_method": "secret",
		"secret":       bhceAPIOpts.Password,
		"username":     bhceAPIOpts.User,
	})
	if err != nil {
		return nil, utils.LogError(err)
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}
	authResponse := &BHCELoginResponse{}
	statusCode, err := c.DoReq(bloodhoundGetBearerTokenURL, "POST", authResponse, headers, nil, requestBody)
	if err != nil {
		return nil, utils.LogError(err)
	}
	if statusCode == 200 {
		// httpClient that handles localhost with subdomains (bloodhound.localhost)
		var customHTTPClient, rerr = bhsdk.GetLocalhostWithSubdomainHttpClient()
		if rerr != nil {
			utils.LogWarningf("Ooof cant make bloodhound.localhost resolving http.Client: error:\n%+v", rerr)
		}
		bearerTokenProvider, err := securityprovider.NewSecurityProviderBearerToken(authResponse.Data.SessionToken)
		if err != nil {
			return nil, utils.LogError(err)
		}
		bhClient, err := bhsdk.NewClientWithResponses(
			bhceAPIOpts.ServerURL,
			bhsdk.WithRequestEditorFn(bearerTokenProvider.Intercept),
			bhsdk.WithBaseURL(bhceAPIOpts.ServerURL+"/"),
			bhsdk.WithHTTPClient(customHTTPClient),
		)
		if err != nil {
			return nil, utils.LogError(err)
		}
		return &BHCEClient{Client: bhClient}, nil
	} else {
		utils.InfoLabelWithColorf("BLOODHOUND", "yellow", "Login failed, status code: %d", statusCode)
	}

	return nil, nil
}

// GetBloodHoundCEAPIVersion ...
func (c *BHCEClient) GetBloodHoundCEAPIVersion() error {
	// Get the API Version from the server
	var params = &bhsdk.GetApiVersionParams{}
	version, err := c.Client.GetApiVersionWithResponse(context.Background(), params)
	if err != nil {
		utils.LogWarningf("Error while getting api version")
		return utils.LogError(err)
	}
	if version.StatusCode() == 200 {
		utils.InfoLabelWithColorf("BLOODHOUND CE API VERSION", "green", "Version: %s", *version.JSON200.Data.ServerVersion)
	} else {
		utils.LogWarningf("Error getting api version. status code: %d", version.StatusCode())
	}
	return nil
}

// SaveCustomQueryBloodHoundCE ...
func (c *BHCEClient) SaveCustomQueryBloodHoundCE(cypherQueryName, cypherQuery string) error {
	cypher := bhsdk.CreateSavedQueryJSONRequestBody{
		Name:  &cypherQueryName,
		Query: &cypherQuery,
	}
	resp, err := c.Client.ListSavedQueriesWithResponse(context.Background(), nil)
	if err != nil {
		return utils.LogError(err)
	}
	// check if the query already exists and if it does, delete it first before creating it again
	for _, v := range *resp.JSON200.Data {
		if *v.Name == cypherQueryName {
			r, err := c.Client.DeleteSavedQueryWithResponse(context.Background(), int32(*v.Id), nil) //nolint:gosec
			if err != nil {
				return utils.LogError(err)
			}
			if r.StatusCode() != 204 {
				utils.LogWarningf("Error deleting cypher query: %s, status: %d", cypherQueryName, r.StatusCode())
			}
		}
	}
	// create the query
	createQueryResp, err := c.Client.CreateSavedQueryWithResponse(context.Background(), &bhsdk.CreateSavedQueryParams{}, cypher)
	if err != nil {
		return utils.LogError(err)
	}
	if createQueryResp.StatusCode() != 201 {
		utils.LogWarningf("Error creating cypher query: %s, status: %d", cypherQueryName, createQueryResp.StatusCode())
	} else {
		utils.InfoLabelWithColorf("BLOODHOUND API", "green", "Cypher query saved: %s", cypherQueryName)
	}

	return nil
}
