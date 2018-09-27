package httphelper

import (
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/shoobyban/slog"
)

// HTTPAuth is used for HTTPRequest
type HTTPAuth struct {
	User     string
	Password string
}

// HTTPRequest is a helper function creating a http requests
func HTTPRequest(method, url string, requestBody io.Reader, auth HTTPAuth) ([]byte, error) {
	body, _, err := HTTPRequestResp(method, url, requestBody, auth)
	return body, err
}

// ParsedHTTPRequest is a helper function creating a http requests parsing JSON or XML response
func ParsedHTTPRequest(method, url string, requestBody io.Reader, auth HTTPAuth) ([]byte, interface{}, error) {
	body, resp, err := HTTPRequestResp(method, url, requestBody, auth)
	if err != nil {
		slog.Infof("Error reading from URL %s %v", url, err)
		return body, resp, err
	}
	var parsedbody interface{}
	if resp.Header.Get("Content-Type") == "application/json" {
		err = json.Unmarshal(body, &parsedbody)
		if err != nil {
			slog.Infof("Error parsing body JSON %s %v", url, err)
		}
	}
	if resp.Header.Get("Content-Type") == "application/xml" {
		err = xml.Unmarshal(body, &parsedbody)
		if err != nil {
			slog.Infof("Error parsing body XML %s %v", url, err)
		}
	}
	return body, parsedbody, err
}

// HTTPRequestResp is a helper function creating a http requests
func HTTPRequestResp(method, url string, requestBody io.Reader, auth HTTPAuth) ([]byte, *http.Response, error) {
	req, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		slog.Infof("Error creating request: %v", err)
		return nil, &http.Response{}, fmt.Errorf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
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
	if resp.StatusCode > 200 {
		slog.Infof("Error reading from URL %s, status: %d, body: %s error:%v", url, resp.StatusCode, string(body), err)
		return body, resp, fmt.Errorf("Error reading from URL %s, status: %d, body: %s error:%v", url, resp.StatusCode, string(body), err)
	}
	//	slog.Infof("response Body: %s", string(body))
	return body, resp, nil
}
