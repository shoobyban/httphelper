package httphelper

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestParsedHTTPRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"a":1}`))
	}))
	defer server.Close()

	_, parsed, err := ParsedHTTPRequest("GET", server.URL, bytes.NewBuffer([]byte{}), HTTPAuth{})

	if err != nil {
		t.Errorf("Error: %v", err)
	}
	expected := map[string]interface{}{"a": 1.0}
	if !reflect.DeepEqual(expected, parsed) {
		t.Errorf("%#v != %#v", parsed, expected)
	}

}

func TestParsedHTTPRequestErr(t *testing.T) {

	_, _, err := ParsedHTTPRequest("GET", "server.URL", bytes.NewBuffer([]byte{}), HTTPAuth{})

	if err == nil {
		t.Errorf("No error")
	}

}
