package pushrelay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClient_RejectsNonHTTPS(t *testing.T) {
	if _, err := NewClient("http://example.com", "sometoken"); err == nil {
		t.Fatal("expected error for http:// base URL, got nil")
	}
}

func TestNewClient_RejectsEmptyToken(t *testing.T) {
	if _, err := NewClient("https://example.com", ""); err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestNewClient_DefaultsBaseURL(t *testing.T) {
	c, err := NewClient("", "sometoken")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.baseURL != DefaultBaseURL {
		t.Fatalf("expected default base URL %q, got %q", DefaultBaseURL, c.baseURL)
	}
}

func TestClient_Send_SendsBearerTokenAndDeviceToken(t *testing.T) {
	var gotAuth, gotPath, gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "test-secret-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.httpClient = srv.Client() // trust the test server's cert

	if err := c.Send(context.Background(), "deadbeef", EnvironmentDevelopment, "title", "body"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotAuth != "Bearer test-secret-token" {
		t.Fatalf("expected Authorization header with bearer token, got %q", gotAuth)
	}
	if gotPath != "/api/push/send" {
		t.Fatalf("expected /api/push/send, got %q", gotPath)
	}
	if !strings.Contains(gotBody, `"deviceToken":"deadbeef"`) {
		t.Fatalf("expected request body to carry the device token, got %q", gotBody)
	}
	// The relay has no state to look this up from, so a sandbox token is
	// only ever routed to Apple's sandbox host if it travels on the request.
	if !strings.Contains(gotBody, `"environment":"development"`) {
		t.Fatalf("expected request body to carry the APNs environment, got %q", gotBody)
	}
}

func TestClient_Send_DefaultsUnknownEnvironmentToProduction(t *testing.T) {
	var gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "test-secret-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.httpClient = srv.Client()

	if err := c.Send(context.Background(), "deadbeef", "", "title", "body"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(gotBody, `"environment":"production"`) {
		t.Fatalf("expected an empty environment to default to production, got %q", gotBody)
	}
}

func TestClient_AuthFailure_DoesNotLeakResponseBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("some internal detail that should never surface"))
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "wrong-token")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.httpClient = srv.Client()

	err = c.Send(context.Background(), "deadbeef", EnvironmentDevelopment, "title", "body")
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if strings.Contains(err.Error(), "internal detail") {
		t.Fatalf("error leaked response body: %v", err)
	}
}
