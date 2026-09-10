package pushrelay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// One unreachable device must not stop the others receiving the alert --
// a single early return would have made the first failure silence the rest.
func TestPublisher_SendsToEveryDeviceEvenWhenOneFails(t *testing.T) {
	var got []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		got = append(got, string(body))
		if strings.Contains(string(body), "broken") {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "tok")
	c.httpClient = srv.Client()
	regs := []Registration{{Token: "broken", Environment: EnvironmentProduction, Label: "Broken Phone"},
		{Token: "good", Environment: EnvironmentDevelopment, Label: "Good Mac"}}
	p := NewPublisher(c, "srv", func() []Registration { return regs }, nil, nil)

	err := p.Publish(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected the failing device to be reported")
	}
	if len(got) != 2 {
		t.Fatalf("expected both devices to be attempted, got %d", len(got))
	}
	if !strings.Contains(got[1], `"deviceToken":"good"`) {
		t.Errorf("second device did not receive the alert: %q", got[1])
	}
}

// APNs reporting a token as gone (relayed as 410) should drop it, not be
// retried on every future alert.
func TestPublisher_PrunesUnregisteredDevice(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "tok")
	c.httpClient = srv.Client()

	var removed []string
	regs := []Registration{{Token: "dead", Environment: EnvironmentProduction, Label: "Old iPad"}}
	p := NewPublisher(c, "srv", func() []Registration { return regs },
		func(token string) error { removed = append(removed, token); return nil }, nil)

	// A prune is now reported rather than silently swallowed -- a device
	// disappearing while the caller is told "sent" is exactly how this
	// went undiagnosed.
	err := p.Publish(context.Background(), "hello")
	if err == nil || !strings.Contains(err.Error(), "unregistered") {
		t.Fatalf("expected the prune to be reported, got %v", err)
	}
	if len(removed) != 1 || removed[0] != "dead" {
		t.Fatalf("expected the dead token to be pruned, got %v", removed)
	}
}

func TestPublisher_NoDevicesIsAnError(t *testing.T) {
	p := NewPublisher(nil, "srv", func() []Registration { return nil }, nil, nil)
	if err := p.Publish(context.Background(), "x"); err == nil {
		t.Fatal("expected an error when nothing is registered")
	} else if !strings.Contains(err.Error(), "no device token") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_TreatsGoneAsUnregistered(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "tok")
	c.httpClient = srv.Client()
	err := c.Send(context.Background(), "d", EnvironmentProduction, "t", "b")
	if !errors.Is(err, ErrTokenUnregistered) {
		t.Fatalf("expected ErrTokenUnregistered, got %v", err)
	}
}

// Tapping "Send Test Alert" on a Mac must prove that Mac can receive, so
// the test targets one device rather than fanning out to whichever other
// device happens to be registered.
func TestSendTestTargetsOnlyThatDevice(t *testing.T) {
	var sent []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		sent = append(sent, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, "tok")
	c.httpClient = srv.Client()
	regs := []Registration{
		{Token: "phone", Environment: EnvironmentProduction, Label: "iPhone"},
		{Token: "mac", Environment: EnvironmentDevelopment, Label: "Mac"},
	}
	find := func(token string) (Registration, bool) {
		for _, r := range regs {
			if r.Token == token {
				return r, true
			}
		}
		return Registration{}, false
	}
	p := NewPublisher(c, "srv", func() []Registration { return regs }, nil, find)

	if err := p.SendTest(context.Background(), "mac", "hi"); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("expected exactly one delivery, got %d", len(sent))
	}
	if !strings.Contains(sent[0], `"deviceToken":"mac"`) {
		t.Errorf("wrong device targeted: %q", sent[0])
	}
	// The Mac is a development build; its token is only valid in sandbox.
	if !strings.Contains(sent[0], `"environment":"development"`) {
		t.Errorf("targeted send lost the device's environment: %q", sent[0])
	}
}

// The failure has to name the device and say what Apple said, instead of
// the bare "Sent" that made this undiagnosable.
func TestSendTestReportsRejectionByDeviceName(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "tok")
	c.httpClient = srv.Client()
	reg := Registration{Token: "mac", Environment: EnvironmentDevelopment, Label: "Anil's Mac"}
	find := func(string) (Registration, bool) { return reg, true }

	var removed []string
	p := NewPublisher(c, "srv", nil, func(tk string) error { removed = append(removed, tk); return nil }, find)

	err := p.SendTest(context.Background(), "mac", "hi")
	if err == nil || !strings.Contains(err.Error(), "Anil's Mac") {
		t.Fatalf("expected the device to be named in the error, got %v", err)
	}
	if len(removed) != 1 {
		t.Errorf("a rejected token should still be pruned, got %v", removed)
	}
}

func TestSendTestRejectsUnknownDevice(t *testing.T) {
	p := NewPublisher(nil, "srv", nil, nil, func(string) (Registration, bool) { return Registration{}, false })
	err := p.SendTest(context.Background(), "nope", "hi")
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("expected a clear not-registered error, got %v", err)
	}
}
