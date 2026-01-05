package client

import (
	"net/http"
	"testing"
)

func TestInitHTTPClientFillsDefaults(t *testing.T) {
	sharedClient = nil
	clientInitialized = false

	InitHTTPClient(&Config{})
	c := GetHTTPClient()

	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("expected *http.Transport, got %T", c.Transport)
	}
	if tr.MaxIdleConns == 0 {
		t.Fatalf("expected MaxIdleConns defaulted, got %d", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost == 0 {
		t.Fatalf("expected MaxIdleConnsPerHost defaulted, got %d", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxConnsPerHost == 0 {
		t.Fatalf("expected MaxConnsPerHost defaulted, got %d", tr.MaxConnsPerHost)
	}
}

func TestConfigureTurboModeSetsPerHostIdleConns(t *testing.T) {
	sharedClient = nil
	clientInitialized = false

	ConfigureTurboMode()
	c := GetHTTPClient()

	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("expected *http.Transport, got %T", c.Transport)
	}
	if tr.MaxIdleConnsPerHost == 0 {
		t.Fatalf("expected MaxIdleConnsPerHost set, got %d", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxConnsPerHost == 0 {
		t.Fatalf("expected MaxConnsPerHost set, got %d", tr.MaxConnsPerHost)
	}
}

