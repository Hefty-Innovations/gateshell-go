package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Hefty-Innovations/gateshell-go/internal/securityaudit"
	"github.com/Hefty-Innovations/gateshell-go/internal/store"
)

type stubSecurityScanner struct{ refresh bool }

func (s *stubSecurityScanner) Scan(refresh bool) securityaudit.Report {
	s.refresh = refresh
	return securityaudit.Report{GeneratedAt: time.Unix(1, 0).UTC(), Source: "gateshell-agent", Platform: "linux", Findings: []securityaudit.Finding{}}
}

func TestSecurityEndpointRequiresAuthAndForwardsRefresh(t *testing.T) {
	scanner := &stubSecurityScanner{}
	server := NewServer(store.NewMemoryStore(1), "secret", "test", "dev", nil, nil, nil, nil, scanner, nil, nil, nil, nil)

	unauthorized := httptest.NewRequest(http.MethodGet, "/api/v1/security", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, unauthorized)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", w.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/security?refresh=1", nil)
	request.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	server.ServeHTTP(w, request)
	body, _ := io.ReadAll(w.Result().Body)
	if w.Code != http.StatusOK || !scanner.refresh || !strings.Contains(string(body), `"source":"gateshell-agent"`) {
		t.Fatalf("status=%d refresh=%v body=%s", w.Code, scanner.refresh, body)
	}
}
