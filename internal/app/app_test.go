package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptionAndMissingMasterKey(t *testing.T) {
	dir := t.TempDir()
	s, e := OpenStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	settings, private, _, e := s.settings()
	if e != nil {
		t.Fatal(e)
	}
	if settings.Address != "10.66.66.1/24" {
		t.Fatal(settings)
	}
	var enc []byte
	if e = s.db.QueryRow("SELECT private FROM settings").Scan(&enc); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(enc, []byte(private)) {
		t.Fatal("private key stored plaintext")
	}
	if _, e = decrypt(s.key, enc, "wrong-scope"); e == nil {
		t.Fatal("AAD not enforced")
	}
	enc[len(enc)-1] ^= 1
	if _, e = decrypt(s.key, enc, "server"); e == nil {
		t.Fatal("tampering accepted")
	}
	s.Close()
	if e = os.Remove(filepath.Join(dir, "master.key")); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenStore(dir); e == nil {
		t.Fatal("missing master key silently replaced")
	}
}
func TestValidationAllocationAndOverlap(t *testing.T) {
	s := defaultSettings()
	for _, bad := range []string{"1.1.1.1\n", "1.1.1.1\r\nAddress = 8.8.8.8"} {
		s.DNS = bad
		if validateSettings(s) == nil {
			t.Fatal("config control accepted")
		}
	}
	s = defaultSettings()
	s.Endpoint = "nas.example:51820"
	if e := validateSettings(s); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"192.168.1.0/24", "8.8.8.1/24", "10.0.0.1/16", "10.0.0.255/24"} {
		if _, e := serverPrefix(bad); e == nil {
			t.Fatal(bad)
		}
	}
	p := []runtimePeer{{Peer: Peer{Address: "10.66.66.2/32"}}}
	address, e := allocate(s.Address, p)
	if e != nil || address != "10.66.66.3/32" {
		t.Fatal(address, e)
	}
	data := []byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24}]},{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16}]}]`)
	for _, addr := range []string{"192.168.1.1/24", "172.17.10.1/24"} {
		if checkOverlap(addr, data) == nil {
			t.Fatal("overlap accepted", addr)
		}
	}
	if e = checkOverlap(s.Address, data); e != nil {
		t.Fatal(e)
	}
}
func request(a *App, method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func TestLocalAuthCSRFAndExport(t *testing.T) {
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "local"})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	secret, e := os.ReadFile(filepath.Join(a.store.dir, "bootstrap-token"))
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]string{"token": strings.TrimSpace(string(secret)), "username": "admin", "password": "a-long-password-123"})
	w := request(a, "POST", "/api/setup", string(body), "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	var session map[string]string
	json.Unmarshal(w.Body.Bytes(), &session)
	csrf := session["csrfToken"]
	w = request(a, "POST", "/api/peers", `{"name":"Phone","deviceType":"phone"}`, "", cookie)
	if w.Code != 403 {
		t.Fatal("csrf not required", w.Code)
	}
	w = request(a, "POST", "/api/peers", `{"name":"Phone","deviceType":"phone"}`, csrf, cookie)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "psk") {
		t.Fatal("peer response leaked secret")
	}
	var peer Peer
	json.Unmarshal(w.Body.Bytes(), &peer)
	w = request(a, "POST", "/api/peers/"+peer.ID+"/config", "{}", csrf, cookie)
	if w.Code != 400 {
		t.Fatal("export without endpoint accepted")
	}
	s := defaultSettings()
	s.Endpoint = "nas.example:51820"
	b, _ := json.Marshal(s)
	w = request(a, "PUT", "/api/settings", string(b), csrf, cookie)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = request(a, "POST", "/api/peers/"+peer.ID+"/config", "{}", csrf, cookie)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "PrivateKey") {
		t.Fatal(w.Code, w.Body)
	}
	w = request(a, "POST", "/api/server/start", "{}", csrf, cookie)
	if w.Code != 503 {
		t.Fatal("development reported real runtime")
	}
	r := httptest.NewRequest("DELETE", "/api/peers/"+peer.ID, nil)
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", "http://evil.invalid")
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross origin mutation accepted")
	}
	w = request(a, "PATCH", "/api/peers/"+peer.ID, `{"enabled":false} garbage`, csrf, cookie)
	if w.Code != 400 {
		t.Fatal("trailing malformed JSON accepted")
	}
	w = request(a, "DELETE", "/api/peers/"+peer.ID, "", csrf, cookie)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestFnosGatewayBinding(t *testing.T) {
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos", BasePath: "/app/fn-wireguard"})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	w := request(a, "GET", "/app/fn-wireguard/api/session", "", "", nil)
	if w.Code != 403 {
		t.Fatal("gateway headers not required")
	}
	r := httptest.NewRequest("GET", "/app/fn-wireguard/api/session", nil)
	r.Header.Set("X-Trim-Isadmin", "true")
	r.Header.Set("X-Trim-Userid", "1")
	r.Header.Set("X-Trim-Username", "NAS admin")
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	c := w.Result().Cookies()[0]
	r = httptest.NewRequest("GET", "/app/fn-wireguard/api/overview", nil)
	r.Header.Set("X-Trim-Isadmin", "true")
	r.Header.Set("X-Trim-Userid", "2")
	r.AddCookie(c)
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("gateway UID session binding not enforced")
	}
}

type failingAdapter struct {
	applies int
	running bool
	fail    bool
	stops   int
}

func (f *failingAdapter) Status() RuntimeStatus {
	return RuntimeStatus{Available: true, Running: f.running, Peers: map[string]Counters{}}
}
func (f *failingAdapter) Apply(_ Settings, _ string, _ []runtimePeer) error {
	f.applies++
	if f.fail {
		f.fail = false
		return errors.New("netlink rejected update")
	}
	return nil
}
func (f *failingAdapter) Start(_ Settings, _ string, _ []runtimePeer) error {
	f.running = true
	return nil
}
func (f *failingAdapter) Stop() error { f.stops++; f.running = false; return nil }
func TestRuntimeFailureRollsBackPeerMutation(t *testing.T) {
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	f := &failingAdapter{}
	a.adapter = f
	a.options.Mode = "production"
	w := httptest.NewRecorder()
	session, e := a.newSession(w, "admin", "uid")
	if e != nil {
		t.Fatal(e)
	}
	cookie := w.Result().Cookies()[0]
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-Trim-Isadmin", "true")
		r.Header.Set("X-Trim-Userid", "uid")
		r.Header.Set("X-CSRF-Token", session.CSRF)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	w = call("POST", "/api/peers", `{"name":"Phone","deviceType":"phone"}`)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var p Peer
	json.Unmarshal(w.Body.Bytes(), &p)
	f.running = true
	f.fail = true
	w = call("PATCH", "/api/peers/"+p.ID, `{"enabled":false}`)
	if w.Code != 503 || f.applies != 2 {
		t.Fatal(w.Code, w.Body, f.applies)
	}
	stored, e := a.store.peers()
	if e != nil || !stored[0].Enabled {
		t.Fatal("failed runtime mutation persisted", e)
	}
	if a.runtimeError != "" {
		t.Fatal("successful rollback incorrectly locked runtime", a.runtimeError)
	}
	w = call("PATCH", "/api/peers/"+p.ID, `{"enabled":false}`)
	if w.Code != 200 || f.applies != 3 {
		t.Fatal("retry required an unnecessary restart", w.Code, w.Body, f.applies)
	}
	stored, e = a.store.peers()
	if e != nil || stored[0].Enabled {
		t.Fatal("retry was not persisted", e)
	}
	w = call("POST", "/api/server/start", "{}")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var desired bool
	if e = a.store.db.QueryRow("SELECT desired FROM lifecycle WHERE id=1").Scan(&desired); e != nil || !desired {
		t.Fatal("desired running state not saved", e)
	}
}

func TestTCPActionBodiesAndConnectionClose(t *testing.T) {
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	server := httptest.NewServer(a)
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	csrf := ""
	call := func(method, path, body string, status int) []byte {
		t.Helper()
		req, e := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Close = true
		req.Header.Set("X-Trim-Isadmin", "true")
		req.Header.Set("X-Trim-Userid", "uid")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal("real TCP request failed", method, path, e)
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		if e != nil {
			t.Fatal("real TCP response failed", method, path, e)
		}
		if resp.StatusCode != status {
			t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
		}
		return b
	}
	login := func() {
		var s map[string]string
		json.Unmarshal(call("GET", "/api/session", "", 200), &s)
		csrf = s["csrfToken"]
	}
	login()
	s := defaultSettings()
	s.Endpoint = "nas.example:51820"
	b, _ := json.Marshal(s)
	call("PUT", "/api/settings", string(b), 200)
	var p Peer
	json.Unmarshal(call("POST", "/api/peers", `{"name":"Phone","deviceType":"phone"}`, 201), &p)
	for range 30 {
		call("POST", "/api/peers/"+p.ID+"/config", "{}", 200)
		call("POST", "/api/server/stop", "{}", 503)
		call("POST", "/api/logout", "{}", 200)
		login()
	}
}

func TestFnosHTTPAdminSessionAndCSRF(t *testing.T) {
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos", BasePath: "/app/fn-wireguard", SecureCookie: false})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	server := httptest.NewServer(a)
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	// Simulate an upgrade from a release that issued a Secure cookie on HTTPS.
	secureURL, e := url.Parse(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	secureURL.Scheme = "https"
	secureURL.Path = "/app/fn-wireguard/api/session"
	jar.SetCookies(secureURL, []*http.Cookie{{Name: "fnwg_session", Value: "old-secure-session", Path: "/app/fn-wireguard", Secure: true, HttpOnly: true}})
	client := &http.Client{Jar: jar}
	csrf := ""
	call := func(method, path, body string, admin bool) (int, []byte, []*http.Cookie) {
		t.Helper()
		req, e := http.NewRequest(method, server.URL+"/app/fn-wireguard/api/"+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("X-Trim-Userid", "nas-admin-uid")
		req.Header.Set("X-Trim-Username", "NAS admin")
		if admin {
			req.Header.Set("X-Trim-Isadmin", "true")
		} else {
			req.Header.Set("X-Trim-Isadmin", "false")
		}
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", csrf)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		data, e := io.ReadAll(resp.Body)
		if e != nil {
			t.Fatal(e)
		}
		return resp.StatusCode, data, resp.Cookies()
	}
	status, data, cookies := call("GET", "session", "", true)
	if status != 200 || len(cookies) != 1 {
		t.Fatal(status, string(data))
	}
	if cookies[0].Name != "fnwg_session_http" || cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("HTTP cookie has incorrect security attributes")
	}
	var session map[string]string
	if e = json.Unmarshal(data, &session); e != nil {
		t.Fatal(e)
	}
	status, data, _ = call("GET", "overview", "", true)
	if status != 200 {
		t.Fatal("cookie jar did not return HTTP session cookie", status, string(data))
	}
	status, _, _ = call("POST", "peers", `{"name":"HTTP phone","deviceType":"phone"}`, true)
	if status != 403 {
		t.Fatal("HTTP bypassed CSRF", status)
	}
	csrf = session["csrfToken"]
	status, data, _ = call("POST", "peers", `{"name":"HTTP phone","deviceType":"phone"}`, true)
	if status != 201 {
		t.Fatal("HTTP authenticated mutation failed", status, string(data))
	}
	status, _, _ = call("GET", "overview", "", false)
	if status != 403 {
		t.Fatal("HTTP nonadministrator accessed API", status)
	}
	status, _, deleted := call("POST", "logout", "{}", true)
	if status != 200 || len(deleted) != 1 || deleted[0].Name != "fnwg_session_http" || deleted[0].MaxAge >= 0 {
		t.Fatal("HTTP logout did not delete active cookie", status)
	}
	status, _, _ = call("GET", "overview", "", true)
	if status != 401 {
		t.Fatal("HTTP logout left session valid", status)
	}
	oldPreserved := false
	for _, c := range jar.Cookies(secureURL) {
		if c.Name == "fnwg_session" && c.Value == "old-secure-session" {
			oldPreserved = true
		}
	}
	if !oldPreserved {
		t.Fatal("HTTP compatibility replaced old Secure cookie")
	}
}

func TestCookieModeNames(t *testing.T) {
	a := &App{options: Options{AuthMode: "fnos", SecureCookie: true}}
	if a.cookieName() != "fnwg_session" {
		t.Fatal("secure mode protocol changed")
	}
	a.options.SecureCookie = false
	if a.cookieName() != "fnwg_session_http" {
		t.Fatal("HTTP fnOS mode reuses Secure cookie name")
	}
	a.options.AuthMode = "local"
	if a.cookieName() != "fnwg_session" {
		t.Fatal("local mode protocol changed")
	}
}
