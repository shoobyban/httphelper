package httphelper

import (
	"crypto/tls"
	"errors"
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
func HTTPRequest(method, url string, requestBody io.Reader, auth HTTPAuth) (interface{}, error) {
	req, err := http.NewRequest(method, url, requestBody)
	if err != nil {
		slog.Infof("Error creating request", err.Error())
		return nil, errors.New("Error creating request")
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
		slog.Infof("Error connecting to URL %s", url, err.Error())
		return nil, errors.New("Error while connecting to URL")
	}
	defer resp.Body.Close()

	slog.Infof("response Status: %v", resp.Status)
	slog.Infof("response Headers: %v", resp.Header)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		slog.Infof("Error reading from URL %s", url, err.Error())
		return nil, errors.New("Error while connecting to URL")
	}
	slog.Infof("response Body: %s", string(body))
	return body, nil
}
