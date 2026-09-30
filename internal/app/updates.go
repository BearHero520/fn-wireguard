package app

import (
	"context"
	"encoding/json"
	"errors"
	"fn-wireguard/internal/buildinfo"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const releaseEndpoint = "https://api.github.com/repos/" + buildinfo.Repository + "/releases/latest"

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type githubRelease struct {
	Tag         string         `json:"tag_name"`
	Notes       string         `json:"body"`
	PublishedAt string         `json:"published_at"`
	Draft       bool           `json:"draft"`
	Prerelease  bool           `json:"prerelease"`
	Assets      []releaseAsset `json:"assets"`
}

type updateResult struct {
	State       string        `json:"state"`
	Current     string        `json:"currentVersion"`
	Latest      string        `json:"latestVersion,omitempty"`
	ReleaseURL  string        `json:"releaseURL"`
	Notes       string        `json:"notes,omitempty"`
	PublishedAt string        `json:"publishedAt,omitempty"`
	CheckedAt   string        `json:"checkedAt"`
	Asset       *releaseAsset `json:"asset,omitempty"`
}

type updateChecker struct {
	mu      sync.Mutex
	client  *http.Client
	checked time.Time
	result  updateResult
	err     error
}

func newUpdateChecker() *updateChecker {
	return &updateChecker{client: &http.Client{
		Timeout: 8 * time.Second,
		// A fixed official endpoint only; do not follow redirects to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func appInfo() any {
	return map[string]string{
		"name": "飞牛 WireGuard", "version": buildinfo.Version,
		"author": buildinfo.Author, "authorURL": buildinfo.AuthorURL,
		"repositoryURL": buildinfo.RepositoryURL, "releasesURL": buildinfo.RepositoryURL + "/releases",
		"architecture": runtime.GOARCH, "platform": runtime.GOOS,
	}
}

// Serialize only version checks, not VPN operations. Cache successful checks
// for five minutes and failures for 30 seconds to avoid GitHub rate limits.
func (u *updateChecker) check(ctx context.Context) (updateResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	ttl := 5 * time.Minute
	if u.err != nil {
		ttl = 30 * time.Second
	}
	if !u.checked.IsZero() && time.Since(u.checked) < ttl {
		return u.result, u.err
	}
	result, err := fetchUpdate(ctx, u.client, buildinfo.Version, runtime.GOARCH)
	// A disconnected browser must not poison another administrator's result.
	if ctx.Err() == nil {
		u.result, u.err, u.checked = result, err, time.Now()
	}
	return result, err
}

func (a *App) checkUpdates(w http.ResponseWriter, r *http.Request) {
	result, err := a.updates.check(r.Context())
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	respond(w, http.StatusOK, result)
}

var stableVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

func versionNumbers(version string) ([3]uint64, error) {
	var result [3]uint64
	m := stableVersion.FindStringSubmatch(version)
	if m == nil {
		return result, errors.New("invalid release version")
	}
	for i := range result {
		result[i], _ = strconv.ParseUint(m[i+1], 10, 64)
	}
	return result, nil
}

func fetchUpdate(ctx context.Context, client *http.Client, current, arch string) (updateResult, error) {
	result := updateResult{Current: current, ReleaseURL: buildinfo.RepositoryURL + "/releases", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseEndpoint, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "fn-wireguard/"+buildinfo.Version)
	resp, err := client.Do(req)
	if err != nil {
		return result, errors.New("update check could not reach GitHub")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		result.State = "unpublished"
		return result, nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		return result, errors.New("GitHub update checks are rate limited")
	case http.StatusOK:
	default:
		return result, errors.New("GitHub update service is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return result, errors.New("invalid GitHub release response")
	}
	var release githubRelease
	if json.Unmarshal(data, &release) != nil || release.Draft || release.Prerelease {
		return result, errors.New("invalid GitHub release response")
	}
	latest, err := versionNumbers(release.Tag)
	if err != nil {
		return result, errors.New("invalid GitHub release response")
	}
	installed, err := versionNumbers(current)
	if err != nil {
		return result, errors.New("invalid installed version")
	}
	result.State = "current"
	for i := range latest {
		if latest[i] > installed[i] {
			result.State = "available"
			break
		}
		if latest[i] < installed[i] {
			result.State = "ahead"
			break
		}
	}
	result.Latest = strings.TrimPrefix(release.Tag, "v")
	result.ReleaseURL = buildinfo.RepositoryURL + "/releases/tag/" + release.Tag
	result.Notes, result.PublishedAt = release.Notes, release.PublishedAt
	// Never pass through arbitrary URLs supplied in release text or asset data.
	if arch == "amd64" || arch == "arm64" {
		filename := "fn-wireguard-" + result.Latest + "-" + arch + ".fpk"
		expectedURL := buildinfo.RepositoryURL + "/releases/download/" + release.Tag + "/" + filename
		for _, asset := range release.Assets {
			if asset.Name == filename && asset.URL == expectedURL && asset.Size > 0 {
				copy := asset
				result.Asset = &copy
				break
			}
		}
	}
	return result, nil
}
