package phlare

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/mr-pmillz/gophlare/utils"
	"github.com/schollz/progressbar/v3"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	HTTP http.Client
}

// NewHTTPClientWithTimeOut creates a new http client with a param for timeout in seconds
func NewHTTPClientWithTimeOut(skipVerify bool, timeout int) *Client {
	timeoutDuration := time.Duration(timeout) * time.Second
	return &Client{
		HTTP: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify}, //nolint:gosec
			},
			Timeout: timeoutDuration,
		},
	}
}

func (c Client) DoReq(u, method string, target interface{}, headers map[string]string, params map[string]string, body []byte) (int, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewBuffer(body)
	}
	req, err := http.NewRequest(method, u, bodyReader)
	if err != nil {
		return 0, utils.LogError(err)
	}

	if body != nil {
		if contentType, ok := headers["Content-Type"]; ok {
			req.Header.Set("Content-Type", contentType)
		}
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	p := url.Values{}
	for k, v := range params {
		p.Add(k, v)
	}
	req.URL.RawQuery = p.Encode()

	// req.Close = true
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, utils.LogError(err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, DecodeResponse(resp, target)
}

func DecodeResponse(resp *http.Response, target interface{}) error {
	if target == nil {
		return nil
	}

	// if the target is a string, then write the body to the file
	if strTarget, ok := target.(string); ok {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return utils.LogError(err)
		}
		outputFile, err := os.Create(strTarget)
		if err != nil {
			return utils.LogError(err)
		}
		defer outputFile.Close()

		if _, err = outputFile.Write(bodyBytes); err != nil {
			return utils.LogError(err)
		}
		return nil
	}
	contentType := resp.Header.Get("Content-Type")
	switch {
	case strings.Contains(contentType, "xml") && !strings.Contains(contentType, "json"):
		return decodeXML(resp.Body, target)
	default:
		return json.NewDecoder(resp.Body).Decode(target)
	}
}

func decodeXML(body io.Reader, target interface{}) error {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, body); err != nil {
		return utils.LogError(err)
	}

	// Try decoding the XML data
	d := xml.NewDecoder(bytes.NewReader(buf.Bytes()))
	d.Strict = false
	err := d.Decode(target)
	if err != nil {
		// If the XML decoding fails, correct the XML data and try again
		buf.Reset()
		if _, err = io.Copy(&buf, body); err != nil {
			return utils.LogError(err)
		}
		if err = xml.EscapeText(&buf, buf.Bytes()); err != nil {
			return utils.LogError(err)
		}
		xmlData := xml.NewDecoder(bytes.NewReader(buf.Bytes()))
		xmlData.Strict = false
		return xmlData.Decode(target)
	}

	return err
}

// downloadZip downloads a ZIP file from the provided URL and saves it to the specified output path.
func downloadZip(url, outputPath, userAgent string) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Mimic curl behavior
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download file, status code: %d", resp.StatusCode)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create progress bar
	bar := progressbar.DefaultBytes(
		resp.ContentLength,
		"downloading",
	)

	// Stream the response body directly to the file with progress bar
	_, err = io.Copy(io.MultiWriter(outFile, bar), resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	return nil
}
