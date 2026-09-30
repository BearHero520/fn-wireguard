package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConfigParserRejectsExecutableAndAmbiguousFields(t *testing.T) {
	private, public, e := privateKey()
	if e != nil {
		t.Fatal(e)
	}
	valid := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.66.66.1/24\nListenPort = 51820\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.66.66.2/32\n", private, public)
	if _, e = parseConfig(valid); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(valid, "ListenPort = 51820", "PostUp = echo unsafe", 1), strings.Replace(valid, "ListenPort = 51820", "SaveConfig = true", 1), strings.Replace(valid, "ListenPort = 51820", "Table = auto", 1), strings.Replace(valid, "ListenPort = 51820", "MTU = 1420", 1), strings.Replace(valid, "Address = 10.66.66.1/24", "Address = 10.66.66.1/24\nAddress = 10.66.66.2/24", 1), valid + "[Interface]\nPrivateKey = " + private, strings.Replace(valid, private, base64.StdEncoding.EncodeToString(make([]byte, 32)), 1)} {
		if _, e = parseConfig(bad); e == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}

func TestServerImportAndClientKeyRestoration(t *testing.T) {
	source, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	target, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	settings, private, public, e := source.store.settings()
	if e != nil {
		t.Fatal(e)
	}
	settings.Endpoint = "nas.example:51820"
	clientPrivate, clientPublic, e := privateKey()
	if e != nil {
		t.Fatal(e)
	}
	peer := runtimePeer{Peer: Peer{ID: token(), Name: "Old phone", DeviceType: "phone", Address: "10.66.66.2/32", PublicKey: clientPublic, Enabled: true, HasConfig: true, CreatedAt: now()}, Private: clientPrivate, PSK: base64.StdEncoding.EncodeToString(randomBytes(32))}
	config, e := serverConfig(settings, private, []runtimePeer{peer})
	if e != nil {
		t.Fatal(e)
	}
	for _, address := range []string{"10.66.66.2/24", "192.168.8.2/32", "10.66.66.1/32"} {
		bad := strings.Replace(config, "10.66.66.2/32", address, 1)
		if _, e = target.planImport(importRequest{Kind: "server", Config: bad}); e == nil {
			t.Fatal("unsafe server route accepted", address)
		}
	}
	cookieWriter := httptest.NewRecorder()
	session, e := target.newSession(cookieWriter, "admin", "uid")
	if e != nil {
		t.Fatal(e)
	}
	cookie := cookieWriter.Result().Cookies()[0]
	call := func(path string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", path, strings.NewReader(string(b)))
		r.Header.Set("X-Trim-Isadmin", "true")
		r.Header.Set("X-Trim-Userid", "uid")
		r.Header.Set("X-CSRF-Token", session.CSRF)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		target.ServeHTTP(w, r)
		return w
	}
	w := call("/api/import/preview", importRequest{Kind: "server", Config: config})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, secret := range []string{private, clientPrivate, peer.PSK} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("preview leaked private material")
		}
	}
	var preview struct {
		PreviewToken string `json:"previewToken"`
	}
	json.Unmarshal(w.Body.Bytes(), &preview)
	w = call("/api/import/apply", map[string]string{"previewToken": preview.PreviewToken})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	restored, e := target.store.peers()
	_, _, restoredPublic, keyErr := target.store.settings()
	if keyErr != nil || restoredPublic != public {
		t.Fatal("import did not replace server public key", keyErr)
	}
	if e != nil || len(restored) != 1 || restored[0].HasConfig || restored[0].Private != "" {
		t.Fatal("server import fabricated client private key", e)
	}
	if _, e = clientConfig(settings, restored[0], public); e == nil {
		t.Fatal("public-only peer exported client config")
	}
	clientConfigText, e := clientConfig(settings, peer, public)
	if e != nil {
		t.Fatal(e)
	}
	clientConfigText = strings.Replace(clientConfigText, "10.66.66.2/32", "10.66.66.2/24", 1)
	w = call("/api/import/preview", importRequest{Kind: "client", Config: clientConfigText})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "complete-peer") || !strings.Contains(w.Body.String(), "normalized") {
		t.Fatal(w.Code, w.Body)
	}
	json.Unmarshal(w.Body.Bytes(), &preview)
	w = call("/api/import/apply", map[string]string{"previewToken": preview.PreviewToken})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	after, e := target.store.peers()
	if e != nil || !after[0].HasConfig || after[0].Private != clientPrivate || after[0].ID != restored[0].ID || after[0].Name != restored[0].Name {
		t.Fatal("client restoration lost existing peer identity", e)
	}
	w = call("/api/import/apply", map[string]string{"previewToken": preview.PreviewToken})
	if w.Code != 400 {
		t.Fatal("single-use token reused")
	}
	w = call("/api/import/preview", importRequest{Kind: "client", Config: clientConfigText})
	if w.Code != 400 {
		t.Fatal("duplicate managed client accepted")
	}
	w = call("/api/import/preview", importRequest{Kind: "server", Config: config})
	if w.Code != 400 {
		t.Fatal("server overwrote existing peers")
	}
}

func TestImportPreviewStaleAndSessionBound(t *testing.T) {
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	s, private, _, _ := a.store.settings()
	cfg, _ := serverConfig(s, private, nil)
	w := httptest.NewRecorder()
	session, _ := a.newSession(w, "admin", "uid")
	cookie := w.Result().Cookies()[0]
	call := func(path string, b any, cookieOverride bool) *httptest.ResponseRecorder {
		data, _ := json.Marshal(b)
		r := httptest.NewRequest("POST", path, strings.NewReader(string(data)))
		r.Header.Set("X-Trim-Isadmin", "true")
		r.Header.Set("X-Trim-Userid", "uid")
		r.Header.Set("X-CSRF-Token", session.CSRF)
		if !cookieOverride {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	w = call("/api/import/preview", importRequest{Kind: "server", Config: cfg}, false)
	var p map[string]any
	json.Unmarshal(w.Body.Bytes(), &p)
	token := p["previewToken"].(string)
	w = call("/api/import/apply", map[string]string{"previewToken": token}, true)
	if w.Code != 401 {
		t.Fatal("preview applied without session")
	}
	s.ListenPort++
	data, _ := json.Marshal(s)
	a.store.db.Exec("UPDATE settings SET value=? WHERE id=1", string(data))
	w = call("/api/import/apply", map[string]string{"previewToken": token}, false)
	if w.Code != 409 {
		t.Fatal("stale preview applied", w.Code, w.Body)
	}
	w = call("/api/import/preview", importRequest{Kind: "server", Config: cfg}, false)
	json.Unmarshal(w.Body.Bytes(), &p)
	token = p["previewToken"].(string)
	expired := a.imports[token]
	expired.Expires = time.Now().Add(-time.Second)
	a.imports[token] = expired
	w = call("/api/import/apply", map[string]string{"previewToken": token}, false)
	if w.Code != 409 {
		t.Fatal("expired token applied", w.Code, w.Body)
	}
	w = call("/api/import/preview", importRequest{Kind: "server", Config: cfg}, false)
	json.Unmarshal(w.Body.Bytes(), &p)
	token = p["previewToken"].(string)
	other := a.imports[token]
	other.Owner = "another-session"
	a.imports[token] = other
	w = call("/api/import/apply", map[string]string{"previewToken": token}, false)
	if w.Code != 400 {
		t.Fatal("other-session preview applied", w.Code, w.Body)
	}
	delete(a.imports, token)
	for range 16 {
		w = call("/api/import/preview", importRequest{Kind: "server", Config: cfg}, false)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	w = call("/api/import/preview", importRequest{Kind: "server", Config: cfg}, false)
	if w.Code != 429 {
		t.Fatal("preview cache unbounded", w.Code, w.Body)
	}
}

func TestUnresolvedRuntimeFailsClosed(t *testing.T) {
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	f := &failingAdapter{}
	a.adapter = f
	a.options.Mode = "production"
	a.runtimeError = "rollback failed"
	s, private, _, e := a.store.settings()
	if e != nil {
		t.Fatal(e)
	}
	config, e := serverConfig(s, private, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.planImport(importRequest{Kind: "server", Config: config}); e == nil {
		t.Fatal("import allowed unresolved runtime state")
	}
	if _, e = a.mutateRuntime(nil, nil); e == nil {
		t.Fatal("peer mutation allowed unresolved runtime state")
	}
	w := httptest.NewRecorder()
	s.ListenPort++
	body, _ := json.Marshal(s)
	r := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(string(body)))
	a.saveSettings(w, r)
	if w.Code != 409 {
		t.Fatal("settings mutation allowed unresolved runtime state")
	}
	if f.applies != 0 {
		t.Fatal("runtime changed despite unresolved state")
	}
}
