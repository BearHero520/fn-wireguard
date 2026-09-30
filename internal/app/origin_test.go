package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOriginWithFnosStrippedPort(t *testing.T) {
	for _, tc := range []struct {
		name, mode, host, origin, fetchSite string
		want                                bool
	}{
		{"local exact", "local", "nas:5000", "http://nas:5000", "", true},
		{"local does not drop port", "local", "nas", "http://nas:5000", "", false},
		{"fnos HTTP", "fnos", "192.168.50.200", "http://192.168.50.200:5000", "", true},
		{"fnos HTTPS", "fnos", "nas.example", "https://nas.example:5001", "same-origin", true},
		{"fnos IPv6", "fnos", "[2001:db8::1]", "http://[2001:db8::1]:5000", "", true},
		{"fnos unchanged host", "fnos", "nas:5000", "http://nas:5000", "", true},
		{"fnos different explicit port", "fnos", "nas:5001", "http://nas:5000", "", false},
		{"foreign hostname", "fnos", "nas", "http://evil.example:5000", "", false},
		{"hostname suffix", "fnos", "nas", "http://nas.evil.example:5000", "", false},
		{"cross site metadata", "fnos", "nas", "http://nas:5000", "cross-site", false},
		{"same site is not same origin", "fnos", "nas", "http://nas:5000", "same-site", false},
		{"opaque origin", "fnos", "nas", "null", "", false},
		{"origin user info", "fnos", "nas", "http://attacker@nas:5000", "", false},
		{"origin path", "fnos", "nas", "http://nas:5000/path", "", false},
		{"origin query", "fnos", "nas", "http://nas:5000?", "", false},
		{"origin fragment", "fnos", "nas", "http://nas:5000#x", "", false},
		{"invalid origin port", "fnos", "nas", "http://nas:99999", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &App{options: Options{AuthMode: tc.mode}}
			r := httptest.NewRequest("POST", "/api/server/start", nil)
			r.Host = tc.host
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			if got := a.sameOrigin(r); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			r.Header.Add("Origin", tc.origin)
			if a.sameOrigin(r) {
				t.Fatal("multiple Origin headers accepted")
			}
		})
	}
}

func TestFnosPortStrippingSaveAndStartStillRequireAuthAndCSRF(t *testing.T) {
	a, err := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos", BasePath: "/app/fn-wireguard"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	adapter := &failingAdapter{}
	a.adapter = adapter
	a.options.Mode = "production"
	sessionWriter := httptest.NewRecorder()
	session, err := a.newSession(sessionWriter, "NAS admin", "1000")
	if err != nil {
		t.Fatal(err)
	}
	cookie := sessionWriter.Result().Cookies()[0]
	call := func(method, path, body, origin, csrf, admin, uid string, withCookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/app/fn-wireguard/api/"+path, strings.NewReader(body))
		r.Host = "192.168.50.200" // Observed fnOS nginx: proxy_set_header Host $host.
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Trim-Isadmin", admin)
		r.Header.Set("X-Trim-Userid", uid)
		r.Header.Set("X-CSRF-Token", csrf)
		if withCookie {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	const origin = "http://192.168.50.200:5000"
	for _, tc := range []struct {
		name, origin, csrf, admin, uid string
		cookie                         bool
		status                         int
	}{
		{"missing token", origin, "", "true", "1000", true, 403},
		{"bad token", origin, "invalid", "true", "1000", true, 403},
		{"nonadmin", origin, session.CSRF, "false", "1000", true, 403},
		{"different user", origin, session.CSRF, "true", "1001", true, 401},
		{"no session", origin, session.CSRF, "true", "1000", false, 401},
		{"external origin", "http://evil.example:5000", session.CSRF, "true", "1000", true, 403},
	} {
		portResult := call("POST", "server/port-check", `{"port":23456}`, tc.origin, tc.csrf, tc.admin, tc.uid, tc.cookie)
		if portResult.Code != tc.status {
			t.Fatal("port check auth guard", tc.name, portResult.Code)
		}
		w := call("POST", "server/start", "{}", tc.origin, tc.csrf, tc.admin, tc.uid, tc.cookie)
		if w.Code != tc.status || adapter.running {
			t.Fatal(tc.name, w.Code, w.Body, adapter.running)
		}
	}
	s := defaultSettings()
	s.Endpoint = "vpn.example.com"
	body, _ := json.Marshal(s)
	w := call("PUT", "settings", string(body), origin, session.CSRF, "true", "1000", true)
	if w.Code != http.StatusOK {
		t.Fatal("gateway settings save failed", w.Code, w.Body)
	}
	w = call("GET", "overview", "", origin, "", "true", "1000", true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "vpn.example.com:51820") {
		t.Fatal("gateway overview did not reflect saved endpoint", w.Code, w.Body)
	}
	w = call("POST", "server/start", "{}", origin, session.CSRF, "true", "1000", true)
	if w.Code != http.StatusOK || !adapter.running {
		t.Fatal("gateway start failed", w.Code, w.Body)
	}
}
