package googleapi

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestProxyEnvRespected verifies that both the full transport chain (used for
// Google API calls) and the plain OAuth HTTP client (used for token exchanges)
// route traffic through HTTP_PROXY when set.
//
// A single proxy server is shared across subtests because
// http.ProxyFromEnvironment caches its result via sync.Once.
func TestProxyEnvRespected(t *testing.T) {
	var hits atomic.Int32

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	t.Setenv("HTTP_PROXY", proxy.URL)

	t.Run("full transport chain", func(t *testing.T) {
		// Mirrors the transport chain built in optionsForAccountScopes.
		baseTransport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"})
		retryTransport := NewRetryTransport(&oauth2.Transport{
			Source: ts,
			Base:   baseTransport,
		})

		client := &http.Client{
			Transport: retryTransport,
			Timeout:   5 * time.Second,
		}

		// Use plain HTTP so the proxy receives a regular forwarded request
		// rather than a CONNECT tunnel (which would need TLS setup).
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://target.example.com/api", nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}

		before := hits.Load()

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request through proxy failed: %v", err)
		}
		defer resp.Body.Close()

		if hits.Load() == before {
			t.Fatal("request did not go through the proxy; HTTP_PROXY was ignored")
		}
	})

	t.Run("oauth token exchange client", func(t *testing.T) {
		// Mirrors the http.Client set via oauth2.HTTPClient context value
		// for token refresh operations.
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
			Timeout:   defaultHTTPTimeout,
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://target.example.com/token", nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}

		before := hits.Load()

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request through proxy failed: %v", err)
		}
		defer resp.Body.Close()

		if hits.Load() == before {
			t.Fatal("OAuth HTTP client did not go through the proxy; HTTP_PROXY was ignored")
		}
	})
}
