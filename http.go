package httphelper

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/shoobyban/mxj"
	"github.com/shoobyban/slog"
)

// HTTPAuth is used for HTTPRequest
type HTTPAuth struct {
	User     string
	Password string
}

// HTTPRequestWithHeaders is a helper function creating a http requests
func HTTPRequestWithHeaders(method, url string, requestBody io.Reader, auth HTTPAuth, headers map[string]string) ([]byte, error) {
	body, _, err := HTTPRequestResp(method, url, requestBody, auth, headers)
	return body, err
}

// ParsedHTTPRequestWithHeaders is a helper function creating a http requests parsing JSON or XML response
func ParsedHTTPRequestWithHeaders(method, url string, requestBody io.Reader, auth HTTPAuth, headers map[string]string) ([]byte, interface{}, error) {
	body, resp, err := HTTPRequestResp(method, url, requestBody, auth, headers)
	if err != nil {
		slog.Infof("Error reading from URL %s %v", url, err)
		return body, resp, err
	}
	var parsedbody interface{}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		err = json.Unmarshal(body, &parsedbody)
		if err != nil {
			slog.Infof("Error parsing body JSON %s %v", url, err)
		}
	} else if strings.Contains(resp.Header.Get("Content-Type"), "xml") {
		m, err := mxj.NewMapXml(body)
		if err != nil {
			slog.Infof("Error parsing body XML %s %v", url, err)
		}
		return body, m, err
	}
	return body, parsedbody, err
}

// HTTPRequest is a helper function creating a http requests
func HTTPRequest(method, url string, requestBody io.Reader, auth HTTPAuth) ([]byte, error) {
	body, _, err := HTTPRequestResp(method, url, requestBody, auth, map[string]string{})
	return body, err
}

// ParsedHTTPRequest is a helper function creating a http requests parsing JSON or XML response
func ParsedHTTPRequest(method, url string, requestBody io.Reader, auth HTTPAuth) ([]byte, interface{}, error) {
	body, resp, err := HTTPRequestResp(method, url, requestBody, auth, map[string]string{})
	if err != nil {
		slog.Infof("Error reading from URL %s %v", url, err)
		return body, resp, err
	}
	var parsedbody interface{}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		err = json.Unmarshal(body, &parsedbody)
		if err != nil {
			slog.Infof("Error parsing body JSON %s %v", url, err)
		}
	} else if strings.Contains(resp.Header.Get("Content-Type"), "xml") {
		m, err := mxj.NewMapXml(body)
		if err != nil {
			slog.Infof("Error parsing body XML %s %v", url, err)
		}
		return body, m, err
	}
	return body, parsedbody, err
}

// HTTPRequestResp is a helper function creating a http requests
func HTTPRequestResp(method, url string, requestBody io.Reader, auth HTTPAuth, headers map[string]string) ([]byte, *http.Response, error) {
	req, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		slog.Infof("Error creating request: %v", err)
		return nil, &http.Response{}, fmt.Errorf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for h, val := range headers {
		req.Header.Set(h, val)
	}
	if auth.User != "" {
		req.SetBasicAuth(auth.User, auth.Password)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   time.Second * 100,
		Transport: tr,
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Infof("Error connecting to URL %s: %v", url, err)
		return nil, resp, fmt.Errorf("Error connecting to URL %s: %v", url, err)
	}
	defer resp.Body.Close()

	slog.Infof("response Status: %v", resp.Status)
	slog.Infof("response Headers: %v", resp.Header)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		slog.Infof("Error reading from URL %s: %v", url, err)
		return body, resp, fmt.Errorf("Error while connecting to URL")
	}
	if resp.StatusCode > 399 {
		slog.Infof("Error reading from URL %s, status: %d, body: %s error:%v", url, resp.StatusCode, string(body), err)
		return body, resp, fmt.Errorf("Error reading from URL %s, status: %d, body: %s error:%v", url, resp.StatusCode, string(body), err)
	}
	//	slog.Infof("response Body: %s", string(body))
	return body, resp, nil
}
