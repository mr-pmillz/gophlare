package flareapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mr-pmillz/gophlare/flareapi/fireworkv2"
	"github.com/mr-pmillz/gophlare/flareapi/fireworkv3"
	"github.com/mr-pmillz/gophlare/flareapi/fireworkv4"
	"github.com/mr-pmillz/gophlare/internal/version"
)

const DefaultBaseURL = "https://api.flare.io"

type Config struct {
	APIKey     string
	Token      string
	TenantID   int
	BaseURL    string
	UserAgent  string
	Timeout    time.Duration
	HTTPClient *http.Client
}

type Client struct {
	V2      *fireworkv2.ClientWithResponses
	V3      *fireworkv3.ClientWithResponses
	V4      *fireworkv4.ClientWithResponses
	session *session
}

type session struct {
	config    Config
	http      *http.Client
	baseURL   *url.URL
	tokenLock chan struct{}
	token     string
	expiresAt time.Time
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

type APIError struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (apiError *APIError) Error() string {
	detail := strings.TrimSpace(string(apiError.Body))
	if len(detail) > 2048 {
		detail = detail[:2048] + "…"
	}
	return fmt.Sprintf("Flare API: HTTP %d %s: %s", apiError.StatusCode, http.StatusText(apiError.StatusCode), detail)
}

func NewClient(config Config) (*Client, error) {
	if config.APIKey == "" && config.Token == "" {
		return nil, fmt.Errorf("a Flare API key or token is required")
	}
	if config.TenantID < 0 || config.Timeout < 0 {
		return nil, fmt.Errorf("tenant ID and timeout must not be negative")
	}
	if config.BaseURL == "" {
		config.BaseURL = DefaultBaseURL
	}
	config.BaseURL = strings.TrimRight(config.BaseURL, "/")
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("invalid Flare API base URL")
	}
	if config.UserAgent == "" {
		config.UserAgent = "gophlare/" + version.String()
	}
	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}
	httpClient := &http.Client{Timeout: config.Timeout}
	if config.HTTPClient != nil {
		*httpClient = *config.HTTPClient
		if httpClient.Timeout == 0 {
			httpClient.Timeout = config.Timeout
		}
	}
	redirect := httpClient.CheckRedirect
	httpClient.CheckRedirect = func(request *http.Request, previous []*http.Request) error {
		if request.URL.Scheme != baseURL.Scheme || request.URL.Host != baseURL.Host {
			return fmt.Errorf("refusing authenticated redirect to another origin")
		}
		if redirect != nil {
			return redirect(request, previous)
		}
		if len(previous) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}
	transport := &session{config: config, http: httpClient, baseURL: baseURL, token: config.Token, tokenLock: make(chan struct{}, 1)}
	if config.Token != "" && config.APIKey != "" {
		transport.expiresAt = time.Now().Add(45 * time.Minute)
	}
	client := &Client{session: transport}
	client.V2, err = fireworkv2.NewClientWithResponses(config.BaseURL, fireworkv2.WithHTTPClient(transport))
	if err != nil {
		return nil, err
	}
	client.V3, err = fireworkv3.NewClientWithResponses(config.BaseURL, fireworkv3.WithHTTPClient(transport))
	if err != nil {
		return nil, err
	}
	client.V4, err = fireworkv4.NewClientWithResponses(config.BaseURL, fireworkv4.WithHTTPClient(transport))
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (transport *session) Do(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	if request.URL.Scheme != transport.baseURL.Scheme || request.URL.Host != transport.baseURL.Host {
		return nil, fmt.Errorf("refusing to send Flare credentials to another origin")
	}
	token, err := transport.accessToken(request.Context())
	if err != nil {
		return nil, err
	}
	request = request.Clone(request.Context())
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", transport.config.UserAgent)
	if request.Header.Get("Accept") == "" {
		request.Header.Set("Accept", "application/json")
	}
	return transport.http.Do(request)
}

func (transport *session) accessToken(ctx context.Context) (string, error) {
	select {
	case transport.tokenLock <- struct{}{}:
		defer func() { <-transport.tokenLock }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if transport.token != "" && (transport.config.APIKey == "" || transport.expiresAt.IsZero() || time.Now().Before(transport.expiresAt)) {
		return transport.token, nil
	}
	body, err := json.Marshal(struct {
		TenantID int `json:"tenant_id,omitempty"`
	}{TenantID: transport.config.TenantID})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, transport.config.BaseURL+"/tokens/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", transport.config.APIKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", transport.config.UserAgent)
	response, err := transport.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("generate Flare token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", responseError(response)
	}
	var tokenResponse struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("decode Flare token: %w", err)
	}
	if tokenResponse.Token == "" {
		return "", fmt.Errorf("flare returned an empty API token")
	}
	transport.token = tokenResponse.Token
	transport.expiresAt = time.Now().Add(45 * time.Minute)
	return transport.token, nil
}

func (client *Client) Execute(ctx context.Context, operation Operation, input Request) (*http.Response, error) {
	request, err := operation.BuildRequest(ctx, client.session.config.BaseURL, input)
	if err != nil {
		return nil, err
	}
	response, err := client.session.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		return nil, responseError(response)
	}
	return response, nil
}

func (client *Client) Call(ctx context.Context, operation Operation, input Request) (*Response, error) {
	response, err := client.Execute(ctx, operation, input)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read Flare response: %w", err)
	}
	return &Response{StatusCode: response.StatusCode, Header: response.Header, Body: body}, nil
}

func responseError(response *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("flare HTTP %d: read error body: %w", response.StatusCode, err)
	}
	return &APIError{StatusCode: response.StatusCode, Header: response.Header.Clone(), Body: body}
}
