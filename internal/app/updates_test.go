package app

import (
	"context"
	"encoding/json"
	"errors"
	"fn-wireguard/internal/buildinfo"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type updateTransport func(*http.Request) (*http.Response, error)

func (f updateTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func releaseResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestUpdateVersionsAndAssets(t *testing.T) {
	for _, tc := range []struct{ current, latest, state string }{
		{"0.1.8", "v0.1.8", "current"}, {"0.1.8", "v0.1.9", "available"},
		{"0.1.9", "v0.1.10", "available"}, {"0.9.9", "1.0.0", "available"},
		{"2.0.0", "v1.99.99", "ahead"},
	} {
		t.Run(tc.current+"/"+tc.latest, func(t *testing.T) {
			filename := "fn-wireguard-" + strings.TrimPrefix(tc.latest, "v") + "-arm64.fpk"
			url := buildinfo.RepositoryURL + "/releases/download/" + tc.latest + "/" + filename
			body, _ := json.Marshal(githubRelease{Tag: tc.latest, Assets: []releaseAsset{{Name: filename, URL: url, Size: 12345}}})
			client := &http.Client{Transport: updateTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != releaseEndpoint || r.Method != "GET" || r.Body != nil || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("User-Agent") != "fn-wireguard/"+buildinfo.Version {
					t.Fatal("update request contains unexpected destination or data")
				}
				return releaseResponse(200, string(body)), nil
			})}
			result, err := fetchUpdate(context.Background(), client, tc.current, "arm64")
			if err != nil || result.State != tc.state || result.Asset == nil || result.Asset.URL != url || result.CheckedAt == "" {
				t.Fatal(result, err)
			}
			result, err = fetchUpdate(context.Background(), client, tc.current, "amd64")
			if err != nil || result.Asset != nil {
				t.Fatal("offered wrong architecture", result, err)
			}
		})
	}
	for _, tag := range []string{"", "v1.2", "v1.2.3-beta.1", "v1.2.3+build", "v01.2.3", "v99999999999999.0.0", "v1.2.3/../../other"} {
		if _, err := versionNumbers(tag); err == nil {
			t.Fatal("invalid stable version accepted", tag)
		}
	}
}

func TestUpdateFailuresAndUntrustedRelease(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		wantError  bool
	}{
		{"not published", `{}`, 404, false},
		{"rate limit", `{}`, 403, true}, {"rate limit 429", `{}`, 429, true},
		{"server failure", `{}`, 503, true}, {"redirect", `{}`, 302, true},
		{"invalid JSON", `oops`, 200, true}, {"empty JSON", `{}`, 200, true},
		{"oversize", strings.Repeat(" ", 1024*1024+1), 200, true},
		{"draft", `{"tag_name":"v0.1.8","draft":true}`, 200, true},
		{"prerelease", `{"tag_name":"v0.1.8","prerelease":true}`, 200, true},
		{"foreign download", `{"tag_name":"v0.1.8","html_url":"https://evil.example/","assets":[{"name":"fn-wireguard-0.1.8-amd64.fpk","browser_download_url":"https://evil.example/install.fpk","size":100}]}`, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: updateTransport(func(*http.Request) (*http.Response, error) { return releaseResponse(tc.status, tc.body), nil })}
			result, err := fetchUpdate(context.Background(), client, buildinfo.Version, "amd64")
			if (err != nil) != tc.wantError || result.Asset != nil || !strings.HasPrefix(result.ReleaseURL, buildinfo.RepositoryURL+"/releases") {
				t.Fatal(result, err)
			}
			if tc.status == 404 && result.State != "unpublished" {
				t.Fatal("404 reported as current version", result)
			}
		})
	}
	client := newUpdateChecker().client
	if client.Timeout != 8*time.Second || client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("missing network bounds")
	}
	client.Transport = updateTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	if _, err := fetchUpdate(context.Background(), client, buildinfo.Version, "amd64"); err == nil {
		t.Fatal("offline update check succeeded")
	}
}

func TestUpdateCacheAndFailureRetry(t *testing.T) {
	u := newUpdateChecker()
	calls := 0
	u.client.Transport = updateTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return releaseResponse(200, `{"tag_name":"v0.1.8"}`), nil
	})
	first, err := u.check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := u.check(context.Background())
	if err != nil || calls != 1 || second.CheckedAt != first.CheckedAt {
		t.Fatal("successful check not cached", err, calls)
	}
	u.checked = time.Now().Add(-6 * time.Minute)
	u.client.Transport = updateTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("offline") })
	if _, err = u.check(context.Background()); err == nil {
		t.Fatal("failure hidden by expired success")
	}
	if _, err = u.check(context.Background()); err == nil || calls != 2 {
		t.Fatal("failure retry was not throttled", calls)
	}
	u.checked = time.Now().Add(-31 * time.Second)
	u.client.Transport = updateTransport(func(*http.Request) (*http.Response, error) { calls++; return releaseResponse(404, `{}`), nil })
	if result, err := u.check(context.Background()); err != nil || result.State != "unpublished" || calls != 3 {
		t.Fatal("failed check cannot recover", result, err, calls)
	}
}

func TestUpdateAuthenticationAndIndependentLock(t *testing.T) {
	a, err := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "local"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	w := httptest.NewRecorder()
	s, err := a.newSession(w, "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]
	var calls atomic.Int32
	entered, finish := make(chan struct{}), make(chan struct{})
	a.updates.client.Transport = updateTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-finish:
			return releaseResponse(200, `{"tag_name":"v0.1.8"}`), nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})
	if w := request(a, "POST", "/api/updates/check", "{}", "", nil); w.Code != 401 {
		t.Fatal("unauthenticated check allowed", w.Code)
	}
	if w := request(a, "POST", "/api/updates/check", "{}", "", cookie); w.Code != 403 {
		t.Fatal("check without CSRF allowed", w.Code)
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized check reached GitHub")
	}
	if w := request(a, "GET", "/api/about", "", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), buildinfo.Author) || !strings.Contains(w.Body.String(), buildinfo.Version) {
		t.Fatal("application identity missing", w.Code, w.Body)
	}
	done := make(chan int, 1)
	go func() { done <- request(a, "POST", "/api/updates/check", "{}", s.CSRF, cookie).Code }()
	defer func() { close(finish); <-done }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("version request did not start")
	}
	settingsDone := make(chan int, 1)
	go func() { settingsDone <- request(a, "GET", "/api/settings", "", "", cookie).Code }()
	select {
	case code := <-settingsDone:
		if code != 200 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("slow GitHub check blocks app state")
	}
}
