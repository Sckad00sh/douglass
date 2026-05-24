package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// okHandler is a stand-in for the real mux: returns 200 with "ok" body so
// tests can distinguish "passed the middleware" from "blocked by middleware".
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
})

// TestHostAllowed pins the loopback allowlist. The middleware rejects any
// request whose Host header is not one of these; DNS rebinding attacks
// land here with attacker-controlled hostnames and get blocked.
func TestHostAllowed(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// loopback variants, with and without ports
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"localhost", true},
		{"localhost:54321", true},
		{"::1", true},
		{"[::1]:8080", true},

		// what a DNS rebinding attack actually looks like
		{"evil.com", false},
		{"evil.com:8080", false},
		{"api.attacker.test:443", false},

		// near-misses to make sure we're not doing a sloppy substring match
		{"127.0.0.1.evil.com", false},
		{"localhost.evil.com", false},
		{"notlocalhost", false},
		{"", false},

		// non-loopback IPs that some might think are "local"
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"169.254.169.254", false}, // cloud metadata, also not us
	}
	for _, c := range cases {
		got := hostAllowed(c.host)
		if got != c.want {
			t.Errorf("hostAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// TestMiddleware_AllowsGoodHost verifies a legitimate same-origin request
// passes through to the wrapped handler.
func TestMiddleware_AllowsGoodHost(t *testing.T) {
	h := localOnly(okHandler)

	req := httptest.NewRequest("GET", "http://127.0.0.1:8080/api/health", nil)
	req.Host = "127.0.0.1:8080"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("good host got %d, want 200", rr.Code)
	}
	if got, _ := io.ReadAll(rr.Body); string(got) != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}

// TestMiddleware_BlocksBadHost is the DNS-rebinding defense in action:
// even with a legitimate-looking path and the right CSRF header, a request
// with a foreign Host header must be rejected.
func TestMiddleware_BlocksBadHost(t *testing.T) {
	h := localOnly(okHandler)

	req := httptest.NewRequest("POST", "http://evil.com/api/open", strings.NewReader(`{"dir":"C:\\"}`))
	req.Host = "evil.com"
	req.Header.Set("X-Requested-By", "douglas")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("bad host got %d, want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "bad Host") {
		t.Errorf("expected bad-host message in body, got %q", rr.Body.String())
	}
}

// TestMiddleware_BlocksMissingCSRFHeader confirms that a same-origin
// request to an API endpoint without X-Requested-By is rejected. This
// blocks cross-origin browser requests from reaching mutating endpoints
// even if the Host check is somehow bypassed.
func TestMiddleware_BlocksMissingCSRFHeader(t *testing.T) {
	h := localOnly(okHandler)

	req := httptest.NewRequest("POST", "http://127.0.0.1/api/open", strings.NewReader(`{}`))
	req.Host = "127.0.0.1"
	// no X-Requested-By header
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("missing CSRF header got %d, want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "X-Requested-By") {
		t.Errorf("expected CSRF message in body, got %q", rr.Body.String())
	}
}

// TestMiddleware_HealthEndpointExempt makes sure /api/health works without
// the CSRF header so external monitoring (or a curl from the shell) can
// probe the server's liveness. This is the only API endpoint exempt from
// the CSRF check.
func TestMiddleware_HealthEndpointExempt(t *testing.T) {
	h := localOnly(okHandler)

	req := httptest.NewRequest("GET", "http://127.0.0.1/api/health", nil)
	req.Host = "127.0.0.1"
	// no X-Requested-By; should still succeed
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("health endpoint got %d, want 200", rr.Code)
	}
}

// TestMiddleware_StaticAssetsExemptFromCSRF verifies that non-API paths
// (the SPA's HTML, JS, CSS) pass through without the CSRF header. The
// guard is specifically API-only because static assets are loaded by the
// browser as resources, not XHR -- and the browser won't send custom
// headers on those loads.
func TestMiddleware_StaticAssetsExemptFromCSRF(t *testing.T) {
	h := localOnly(okHandler)

	for _, path := range []string{"/", "/index.html", "/app.js", "/app.css"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1"+path, nil)
		req.Host = "127.0.0.1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s got %d, want 200 (no CSRF needed on static assets)", path, rr.Code)
		}
	}
}

// TestMiddleware_SecurityHeadersPresent verifies the defense-in-depth
// headers (CSP, X-Frame-Options, nosniff, no-referrer) ride along on
// every response, including error replies. This is the catch-all in
// case a future code change introduces a hole that CSP would catch.
func TestMiddleware_SecurityHeadersPresent(t *testing.T) {
	h := localOnly(okHandler)

	// Test on both a successful path and a blocked one -- headers must
	// be set BEFORE the response is committed so even errors carry them.
	cases := []struct {
		name, host, path string
		csrf             string
		wantStatus       int
	}{
		{"success", "127.0.0.1", "/api/health", "", 200},
		{"blocked-host", "evil.com", "/api/health", "", 403},
		{"missing-csrf", "127.0.0.1", "/api/open", "", 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+c.host+c.path, nil)
			req.Host = c.host
			if c.csrf != "" {
				req.Header.Set("X-Requested-By", c.csrf)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != c.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, c.wantStatus)
			}
			// CSP must be set and must include the strict directives we rely on.
			csp := rr.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Error("missing Content-Security-Policy header")
			}
			for _, must := range []string{
				"default-src 'self'",
				"script-src 'self'",
				"frame-ancestors 'none'",
				"base-uri 'none'",
			} {
				if !strings.Contains(csp, must) {
					t.Errorf("CSP missing %q; got %q", must, csp)
				}
			}
			if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want DENY", got)
			}
			if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q, want no-referrer", got)
			}
		})
	}
}
