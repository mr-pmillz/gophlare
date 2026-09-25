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

// DoReq performs a request and returns only the status code. Its signature is
// deliberately unchanged: bloodhound/api.go and external SDK consumers call it.
// Use DoReqWithHeaders when response headers matter — Flare reports quota state
// only in headers.
func (c Client) DoReq(u, method string, target any, headers map[string]string, params map[string]string, body []byte) (int, error) {
	statusCode, _, err := c.DoReqWithHeaders(u, method, target, headers, params, body)
	return statusCode, err
}

// DoReqWithHeaders performs a request and additionally returns the response
// headers. Headers are returned for non-2xx responses too, so a 429's quota
// headers are not lost. A transport failure returns a nil header.
func (c Client) DoReqWithHeaders(u, method string, target any, headers map[string]string, params map[string]string, body []byte) (int, http.Header, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewBuffer(body)
	}
	req, err := http.NewRequest(method, u, bodyReader)
	if err != nil {
		return 0, nil, utils.LogError(err)
	}

	if body != nil {
		if contentType, ok := headers["Content-Type"]; ok {
			req.Header.Set("Content-Type", contentType)
		}
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Merge params into any query already in u, such as the cursor of a URL
	// returned by the API. Without params the query is left byte-for-byte.
	if len(params) > 0 {
		q := req.URL.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	// req.Close = true
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, utils.LogError(err)
	}
	defer resp.Body.Close()

	// Don't attempt JSON/XML decode on error responses — the body is
	// typically plain text (e.g. "upstream request timeout" on a 504)
	// and the decode failure ("invalid character 'u'") otherwise masks
	// the real HTTP status from the caller. Drain the body so the
	// connection can be reused, and let the caller branch on statusCode.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Header, nil
	}

	return resp.StatusCode, resp.Header, DecodeResponse(resp, target)
}

func DecodeResponse(resp *http.Response, target any) error {
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

func decodeXML(body io.Reader, target any) error {
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
