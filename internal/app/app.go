package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Options struct {
	DataDir, WebDir, Mode, AuthMode, BasePath string
	SecureCookie                              bool
	LANProvider                               LANProvider
}
type App struct {
	store        *Store
	adapter      Adapter
	options      Options
	mu           sync.Mutex
	rates        map[string]rateEntry
	runtimeError string
	imports      map[string]importPlan
	lan          LANProvider
	lastLANScan  time.Time
	updates      *updateChecker
}

func New(o Options) (*App, error) {
	if o.AuthMode != "local" && o.AuthMode != "fnos" {
		return nil, errors.New("auth mode must be local or fnos")
	}
	s, e := OpenStore(o.DataDir)
	if e != nil {
		return nil, e
	}
	if o.AuthMode == "local" {
		if e = s.bootstrap(); e != nil {
			s.Close()
			return nil, e
		}
	}
	a := &App{store: s, adapter: NewAdapter(o.Mode), options: o, rates: map[string]rateEntry{}, imports: map[string]importPlan{}, updates: newUpdateChecker()}
	a.lan = o.LANProvider
	if a.lan == nil {
		a.lan = systemLAN{mode: o.Mode}
	}
	if o.Mode == "production" || o.LANProvider != nil {
		if e = a.initializeAccess(); e != nil {
			s.Close()
			return nil, e
		}
	}
	var desired bool
	if e = s.db.QueryRow("SELECT desired FROM lifecycle WHERE id=1").Scan(&desired); e != nil {
		s.Close()
		return nil, e
	}
	if desired && o.Mode == "production" {
		settings, priv, _, se := s.settings()
		peers, pe := s.peers()
		if se != nil {
			a.runtimeError = se.Error()
		} else if pe != nil {
			a.runtimeError = pe.Error()
		} else if re := a.adapter.Start(settings, priv, peers); re != nil {
			a.runtimeError = "Unable to restore server: " + re.Error()
		}
	}
	return a, nil
}
func (a *App) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var runtimeErr error
	if a.options.Mode == "production" {
		runtimeErr = a.adapter.Stop()
	}
	return errors.Join(runtimeErr, a.store.Close())
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'")
	if a.options.BasePath != "" && r.URL.Path == a.options.BasePath {
		http.Redirect(w, r, a.options.BasePath+"/", http.StatusPermanentRedirect)
		return
	}
	if p := a.options.BasePath; p != "" && (r.URL.Path == p || strings.HasPrefix(r.URL.Path, p+"/")) {
		r = r.Clone(r.Context())
		u := *r.URL
		r.URL = &u
		r.URL.Path = strings.TrimPrefix(r.URL.Path, p)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
		// Consume bounded bodies before responding, including auth failures and
		// actions without JSON fields. Leaving POST bytes unread can reset TCP
		// connections before clients receive the response on some platforms.
		if r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
			r.Body.Close()
			if err != nil {
				fail(w, 400, "cannot read request body")
				return
			}
			if len(body) > 64*1024 {
				r.Close = true
				fail(w, 413, "request body exceeds 64 KiB")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		a.mu.Lock()
		if a.authRoute(w, r) {
			a.mu.Unlock()
			return
		}
		// Authentication and CSRF stay under the normal lock; slow external
		// update checks must not block service stop or device changes.
		if r.URL.Path == "/api/updates/check" && r.Method == "POST" {
			a.mu.Unlock()
			a.checkUpdates(w, r)
			return
		}
		defer a.mu.Unlock()
		a.api(w, r)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(w, 405, "method not allowed")
		return
	}
	if a.options.AuthMode == "fnos" && (r.Header.Get("X-Trim-Isadmin") != "true" || r.Header.Get("X-Trim-Userid") == "") {
		fail(w, 403, "A fnOS administrator session is required")
		return
	}
	clean := filepath.Clean(filepath.FromSlash(r.URL.Path))
	if strings.Contains(clean, "..") || strings.Contains(clean, "\\") && os.PathSeparator != '\\' {
		fail(w, 400, "invalid path")
		return
	}
	path := filepath.Join(a.options.WebDir, strings.TrimLeft(clean, "/\\"))
	info, e := os.Stat(path)
	if e != nil || info.IsDir() {
		path = filepath.Join(a.options.WebDir, "index.html")
	}
	if _, e = os.Stat(path); e != nil {
		fail(w, 503, "frontend is not installed")
		return
	}
	http.ServeFile(w, r, path)
}
func (a *App) enrich(peers []runtimePeer, status RuntimeStatus) []Peer {
	out := make([]Peer, 0, len(peers))
	for _, p := range peers {
		v := p.Peer
		if c, ok := status.Peers[p.PublicKey]; ok {
			v.ReceivedBytes = c.RX
			v.SentBytes = c.TX
			if c.Handshake > 0 {
				t := time.Unix(c.Handshake, 0).UTC()
				s := t.Format(time.RFC3339)
				v.LastHandshake = &s
				v.Online = v.Enabled && time.Since(t) >= 0 && time.Since(t) < 3*time.Minute
			}
		}
		out = append(out, v)
	}
	return out
}
func (a *App) overview() (any, error) {
	s, _, pub, e := a.store.settings()
	if e != nil {
		return nil, e
	}
	peers, e := a.store.peers()
	if e != nil {
		return nil, e
	}
	status := a.adapter.Status()
	if a.runtimeError != "" {
		status.Reason = a.runtimeError
	}
	views := a.enrich(peers, status)
	stats := struct {
		Total, Enabled, Online int
		RX, TX                 uint64
	}{}
	for _, p := range views {
		stats.Total++
		if p.Enabled {
			stats.Enabled++
		}
		if p.Online {
			stats.Online++
		}
		stats.RX += p.ReceivedBytes
		stats.TX += p.SentBytes
	}
	audit, e := a.store.audits()
	if e != nil {
		return nil, e
	}
	return map[string]any{"server": map[string]any{"running": status.Running, "available": status.Available, "reason": status.Reason, "interface": iface, "publicKey": pub, "listenPort": s.ListenPort, "actualListenPort": status.ListenPort, "address": s.Address, "endpoint": s.Endpoint}, "stats": map[string]any{"totalPeers": stats.Total, "enabledPeers": stats.Enabled, "onlinePeers": stats.Online, "receivedBytes": stats.RX, "sentBytes": stats.TX}, "recentActivity": audit}, nil
}
func (a *App) api(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/about" && r.Method == "GET":
		respond(w, 200, appInfo())
	case r.URL.Path == "/api/lan" && r.Method == "GET", r.URL.Path == "/api/lan/scan" && r.Method == "POST":
		a.lanRoute(w, r)
	case r.URL.Path == "/api/server/port-check" && r.Method == "POST":
		a.checkPort(w, r)
	case r.URL.Path == "/api/import/preview" && r.Method == "POST":
		a.previewImport(w, r)
	case r.URL.Path == "/api/import/apply" && r.Method == "POST":
		a.applyImport(w, r)
	case r.URL.Path == "/api/server/config" && r.Method == "POST":
		a.exportServerConfig(w, r)
	case r.URL.Path == "/api/overview" && r.Method == "GET":
		v, e := a.overview()
		if e != nil {
			fail(w, 500, "cannot read overview")
		} else {
			respond(w, 200, v)
		}
	case r.URL.Path == "/api/audit" && r.Method == "GET":
		v, e := a.store.audits()
		if e != nil {
			fail(w, 500, "cannot read activity")
		} else {
			respond(w, 200, v)
		}
	case r.URL.Path == "/api/settings" && r.Method == "GET":
		s, _, _, e := a.store.settings()
		if e != nil {
			fail(w, 500, "cannot read settings")
		} else {
			respond(w, 200, s)
		}
	case r.URL.Path == "/api/settings" && r.Method == "PUT":
		a.saveSettings(w, r)
	case r.URL.Path == "/api/peers" && r.Method == "GET":
		p, e := a.store.peers()
		if e != nil {
			fail(w, 500, "cannot read peers")
		} else {
			respond(w, 200, a.enrich(p, a.adapter.Status()))
		}
	case r.URL.Path == "/api/peers" && r.Method == "POST":
		a.createPeer(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/peers/"):
		a.peerRoute(w, r)
	case (r.URL.Path == "/api/server/start" || r.URL.Path == "/api/server/stop") && r.Method == "POST":
		a.server(w, r)
	default:
		fail(w, 404, "API endpoint not found")
	}
}
func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) {
	var s Settings
	if e := decode(r, &s); e != nil {
		fail(w, 400, e.Error())
		return
	}
	s = normalizeSettings(s)
	var prepErr error
	s, prepErr = a.prepareAccess(s)
	if prepErr != nil {
		fail(w, 400, prepErr.Error())
		return
	}
	if e := validateSettings(s); e != nil {
		fail(w, 400, e.Error())
		return
	}
	old, _, _, e := a.store.settings()
	if e != nil {
		fail(w, 500, "cannot read settings")
		return
	}
	// Endpoint and DNS are client export settings, not changes to the live
	// interface. Saving them must not depend on WireGuard being available.
	if old.Address != s.Address || old.ListenPort != s.ListenPort || accessChanged(old, s) {
		if a.options.Mode == "production" && a.runtimeError != "" {
			fail(w, 409, "runtime state is unresolved; successfully stop or restart the server before changing settings")
			return
		}
		status := a.adapter.Status()
		if status.Running || a.options.Mode == "production" && (status.Reason != "" || !status.Available) {
			fail(w, 409, "stop the server before changing settings")
			return
		}
	}
	peers, e := a.store.peers()
	if e != nil {
		fail(w, 500, "cannot read peers")
		return
	}
	if old.Address != s.Address && len(peers) > 0 {
		fail(w, 409, "remove all peers before changing the server address")
		return
	}
	for _, peer := range peers {
		if _, e := accessTargets(s, peer.Peer); e != nil {
			fail(w, 400, e.Error())
			return
		}
	}
	j, _ := json.Marshal(s)
	tx, e := a.store.db.Begin()
	if e != nil {
		fail(w, 500, "cannot save settings")
		return
	}
	defer tx.Rollback()
	_, e = tx.Exec("UPDATE settings SET value=? WHERE id=1", string(j))
	if e == nil {
		e = auditTx(tx, "settings.update", "server")
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		fail(w, 500, "cannot save settings")
		return
	}
	respond(w, 200, s)
}
func (a *App) mutateRuntime(old, next []runtimePeer) (bool, error) {
	if a.options.Mode == "production" && a.runtimeError != "" {
		return false, errors.New("runtime state is unresolved; successfully stop or restart the server before changing peers")
	}
	status := a.adapter.Status()
	if !status.Running {
		if a.options.Mode == "production" && (status.Reason != "" || !status.Available) {
			return false, errors.New(status.Reason)
		}
		return false, nil
	}
	s, priv, _, e := a.store.settings()
	if e != nil {
		return false, e
	}
	if e = a.adapter.Apply(s, priv, next); e != nil {
		var unchanged *runtimeUnchangedError
		if errors.As(e, &unchanged) {
			return false, e
		}
		rollback := a.adapter.Apply(s, priv, old)
		if rollback != nil {
			a.runtimeError = fmt.Sprintf("Runtime update and rollback failed: %v; %v", e, rollback)
		} else {
			a.runtimeError = ""
		}
		return false, e
	}
	a.runtimeError = ""
	return true, nil
}
func (a *App) rollbackRuntime(old []runtimePeer) {
	s, priv, _, e := a.store.settings()
	if e == nil {
		e = a.adapter.Apply(s, priv, old)
	}
	if e != nil {
		a.runtimeError = "Database commit failed and runtime rollback failed: " + e.Error()
	} else {
		a.runtimeError = ""
	}
}
func (a *App) createPeer(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name       string `json:"name"`
		DeviceType string `json:"deviceType"`
	}
	if e := decode(r, &b); e != nil {
		fail(w, 400, e.Error())
		return
	}
	if e := validateName(b.Name); e != nil {
		fail(w, 400, e.Error())
		return
	}
	switch b.DeviceType {
	case "phone", "computer", "tablet", "other":
	default:
		fail(w, 400, "invalid device type")
		return
	}
	old, e := a.store.peers()
	if e != nil {
		fail(w, 500, "cannot read peers")
		return
	}
	s, _, _, e := a.store.settings()
	if e != nil {
		fail(w, 500, "cannot read settings")
		return
	}
	addr, e := allocate(s.Address, old)
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	priv, pub, e := privateKey()
	if e != nil {
		fail(w, 500, "cannot generate peer key")
		return
	}
	p := runtimePeer{Peer: Peer{ID: token(), Name: strings.TrimSpace(b.Name), DeviceType: b.DeviceType, Address: addr, PublicKey: pub, Enabled: true, HasConfig: true, CreatedAt: now()}, Private: priv, PSK: base64.StdEncoding.EncodeToString(randomBytes(32))}
	next := append(append([]runtimePeer{}, old...), p)
	changed, e := a.mutateRuntime(old, next)
	if e != nil {
		fail(w, 503, e.Error())
		return
	}
	tx, e := a.store.db.Begin()
	if e == nil {
		e = a.store.insertPeer(tx, p)
		if e == nil {
			e = auditTx(tx, "peer.create", p.Name)
		}
		if e == nil {
			e = tx.Commit()
		} else {
			tx.Rollback()
		}
	}
	if e != nil {
		if tx != nil {
			tx.Rollback()
		}
		if changed {
			a.rollbackRuntime(old)
		}
		fail(w, 500, "cannot save peer")
		return
	}
	respond(w, 201, p.Peer)
}
func (a *App) peerRoute(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/peers/"), "/")
	if len(parts) > 2 || parts[0] == "" {
		fail(w, 404, "peer not found")
		return
	}
	old, e := a.store.peers()
	if e != nil {
		fail(w, 500, "cannot read peers")
		return
	}
	index := -1
	for i, p := range old {
		if p.ID == parts[0] {
			index = i
			break
		}
	}
	if index < 0 {
		fail(w, 404, "peer not found")
		return
	}
	p := old[index]
	if len(parts) == 2 && parts[1] == "config" && r.Method == "POST" {
		s, _, pub, e := a.store.settings()
		if e != nil {
			fail(w, 500, "cannot read settings")
			return
		}
		config, e := clientConfig(s, p, pub)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		tx, e := a.store.db.Begin()
		if e == nil {
			e = auditTx(tx, "peer.config.export", p.Name)
			if e == nil {
				e = tx.Commit()
			} else {
				tx.Rollback()
			}
		}
		if e != nil {
			fail(w, 500, "cannot record configuration export")
			return
		}
		respond(w, 200, map[string]string{"filename": "fnwg-" + p.ID[:8] + ".conf", "config": config})
		return
	}
	if len(parts) != 1 {
		fail(w, 404, "API endpoint not found")
		return
	}
	next := append([]runtimePeer{}, old...)
	action := ""
	switch r.Method {
	case "PATCH":
		var b struct {
			Name           *string   `json:"name"`
			Enabled        *bool     `json:"enabled"`
			AccessMode     *string   `json:"accessMode"`
			AllowedDevices *[]string `json:"allowedDevices"`
		}
		if e = decode(r, &b); e != nil {
			fail(w, 400, e.Error())
			return
		}
		if b.Name == nil && b.Enabled == nil && b.AccessMode == nil {
			fail(w, 400, "provide name or enabled")
			return
		}
		if b.Name != nil {
			if e = validateName(*b.Name); e != nil {
				fail(w, 400, e.Error())
				return
			}
			p.Name = strings.TrimSpace(*b.Name)
		}
		if b.Enabled != nil {
			p.Enabled = *b.Enabled
		}
		if b.AllowedDevices != nil && b.AccessMode == nil {
			fail(w, 400, "provide access mode with device targets")
			return
		}
		if b.AccessMode != nil {
			settings, _, _, err := a.store.settings()
			if err != nil {
				fail(w, 500, "cannot read settings")
				return
			}
			p.AccessMode = *b.AccessMode
			p.AllowedDevices = nil
			if b.AllowedDevices != nil {
				p.AllowedDevices = *b.AllowedDevices
			}
			if err = validateTargets(p.AccessMode, settings.LANSubnet, p.AllowedDevices, true); err != nil {
				fail(w, 400, err.Error())
				return
			}
			if _, err = accessTargets(settings, p.Peer); err != nil {
				fail(w, 400, err.Error())
				return
			}
		}
		next[index] = p
		action = "peer.update"
	case "DELETE":
		next = append(next[:index], next[index+1:]...)
		action = "peer.delete"
	default:
		fail(w, 405, "method not allowed")
		return
	}
	changed, e := a.mutateRuntime(old, next)
	if e != nil {
		fail(w, 503, e.Error())
		return
	}
	tx, e := a.store.db.Begin()
	if e == nil {
		if r.Method == "DELETE" {
			_, e = tx.Exec("DELETE FROM peers WHERE id=?", p.ID)
		} else {
			_, e = tx.Exec("UPDATE peers SET name=?,enabled=? WHERE id=?", p.Name, p.Enabled, p.ID)
			if e == nil {
				e = writePeerAccess(tx, p.Peer)
			}
		}
		if e == nil {
			e = auditTx(tx, action, p.Name)
		}
		if e == nil {
			e = tx.Commit()
		} else {
			tx.Rollback()
		}
	}
	if e != nil {
		if tx != nil {
			tx.Rollback()
		}
		if changed {
			a.rollbackRuntime(old)
		}
		fail(w, 500, "cannot save peer change")
		return
	}
	if r.Method == "DELETE" {
		respond(w, 200, map[string]bool{"ok": true})
	} else {
		respond(w, 200, p.Peer)
	}
}
func (a *App) server(w http.ResponseWriter, r *http.Request) {
	s, priv, _, e := a.store.settings()
	if e != nil {
		fail(w, 500, "cannot read settings")
		return
	}
	peers, e := a.store.peers()
	if e != nil {
		fail(w, 500, "cannot read peers")
		return
	}
	action := "server.stop"
	if strings.HasSuffix(r.URL.Path, "/start") {
		action = "server.start"
		e = a.adapter.Start(s, priv, peers)
	} else {
		e = a.adapter.Stop()
	}
	if e != nil {
		a.runtimeError = e.Error()
		fail(w, 503, e.Error())
		return
	}
	a.runtimeError = ""
	tx, e := a.store.db.Begin()
	if e == nil {
		_, e = tx.Exec("UPDATE lifecycle SET desired=? WHERE id=1", action == "server.start")
		if e == nil {
			e = auditTx(tx, action, iface)
		}
		if e == nil {
			e = tx.Commit()
		} else {
			tx.Rollback()
		}
	}
	if e != nil {
		a.runtimeError = "Runtime changed but audit persistence failed"
		fail(w, 500, a.runtimeError)
		return
	}
	v, e := a.overview()
	if e != nil {
		fail(w, 500, "cannot read overview")
	} else {
		respond(w, 200, v)
	}
}
