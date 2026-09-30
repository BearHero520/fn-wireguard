package app

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type session struct {
	Username, UID, CSRF string
	Expires             int64
}
type rateEntry struct {
	Count int
	Start time.Time
}

func (a *App) cookieName() string {
	if a.options.AuthMode == "fnos" && !a.options.SecureCookie {
		return "fnwg_session_http"
	}
	return "fnwg_session"
}

func (a *App) limited(r *http.Request) bool {
	key, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		key = r.RemoteAddr
	}
	t := time.Now()
	v := a.rates[key]
	if t.Sub(v.Start) > time.Minute {
		v = rateEntry{Start: t}
	}
	v.Count++
	if len(a.rates) >= 2048 {
		for k, x := range a.rates {
			if t.Sub(x.Start) > time.Minute {
				delete(a.rates, k)
			}
		}
		if len(a.rates) >= 2048 {
			return true
		}
	}
	a.rates[key] = v
	return v.Count > 10
}
func (a *App) cookie(w http.ResponseWriter, value string, expires time.Time) {
	p := a.options.BasePath
	if p == "" {
		p = "/"
	}
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(), Value: value, Path: p, HttpOnly: true, Secure: a.options.SecureCookie, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(time.Until(expires).Seconds())})
}
func (a *App) newSession(w http.ResponseWriter, username, uid string) (session, error) {
	s := session{username, uid, token(), time.Now().Add(12 * time.Hour).Unix()}
	t := token()
	tx, e := a.store.db.Begin()
	if e != nil {
		return s, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("DELETE FROM sessions WHERE expires<?", time.Now().Unix()); e != nil {
		return s, e
	}
	var n int
	if e = tx.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&n); e != nil {
		return s, e
	}
	if n >= 100 {
		if _, e = tx.Exec("DELETE FROM sessions WHERE hash IN (SELECT hash FROM sessions ORDER BY expires LIMIT 10)"); e != nil {
			return s, e
		}
	}
	if _, e = tx.Exec("INSERT INTO sessions VALUES(?,?,?,?,?)", digest(t), username, uid, s.CSRF, s.Expires); e != nil {
		return s, e
	}
	if e = tx.Commit(); e != nil {
		return s, e
	}
	a.cookie(w, t, time.Unix(s.Expires, 0))
	return s, nil
}
func (a *App) session(r *http.Request) (session, error) {
	var s session
	c, e := r.Cookie(a.cookieName())
	if e != nil {
		return s, e
	}
	e = a.store.db.QueryRow("SELECT username,uid,csrf,expires FROM sessions WHERE hash=?", digest(c.Value)).Scan(&s.Username, &s.UID, &s.CSRF, &s.Expires)
	if e != nil {
		return s, e
	}
	if s.Expires < time.Now().Unix() {
		return s, errors.New("expired session")
	}
	if a.options.AuthMode == "fnos" && s.UID != r.Header.Get("X-Trim-Userid") {
		return s, errors.New("gateway user changed")
	}
	return s, nil
}
func (a *App) sameOrigin(r *http.Request) bool {
	if len(r.Header.Values("Origin")) > 1 {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	// fnOS /app/ proxies with `Host $host`, which removes the public port.
	// Only the trusted Unix-socket gateway mode may accept that specific loss.
	// Authentication, UID-bound sessions and CSRF checks still run below.
	if a.options.AuthMode != "fnos" || u.Port() == "" {
		return false
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return false
	}
	gateway, e := url.Parse("//" + r.Host)
	if e != nil || gateway.Hostname() == "" || gateway.Port() != "" || gateway.User != nil || gateway.Path != "" || gateway.RawQuery != "" || gateway.Fragment != "" {
		return false
	}
	// Supporting plain HTTP means fetch metadata may be absent. When the
	// browser does provide it, never treat a cross-origin request as same-origin.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	return strings.EqualFold(u.Hostname(), gateway.Hostname())
}
func (a *App) authRoute(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	fnos := a.options.AuthMode == "fnos"
	if fnos && (r.Header.Get("X-Trim-Isadmin") != "true" || strings.TrimSpace(r.Header.Get("X-Trim-Userid")) == "" || len(r.Header.Get("X-Trim-Userid")) > 128) {
		fail(w, 403, "A fnOS administrator session is required")
		return true
	}
	if r.Method != "GET" && r.Method != "HEAD" && !a.sameOrigin(r) {
		fail(w, 403, "request origin is not allowed")
		return true
	}
	switch {
	case path == "/api/setup" && r.Method == "GET":
		yes, e := a.store.initialized()
		if fnos {
			yes = true
		}
		if e != nil {
			fail(w, 500, "cannot read setup state")
		} else {
			respond(w, 200, map[string]bool{"initialized": yes})
		}
		return true
	case (path == "/api/setup" || path == "/api/login") && r.Method == "POST":
		if fnos {
			fail(w, 403, "Local login is disabled in fnOS authentication mode")
			return true
		}
		if a.limited(r) {
			fail(w, 429, "Too many authentication attempts; try again later")
			return true
		}
		var b struct{ Token, Username, Password string }
		if e := decode(r, &b); e != nil {
			fail(w, 400, e.Error())
			return true
		}
		if path == "/api/setup" {
			yes, e := a.store.initialized()
			if e != nil {
				fail(w, 500, "cannot read setup state")
				return true
			}
			if yes {
				fail(w, 409, "administrator is already initialized")
				return true
			}
			expected, e := os.ReadFile(filepath.Join(a.store.dir, "bootstrap-token"))
			if e != nil || !equal([]byte(strings.TrimSpace(string(expected))), []byte(b.Token)) {
				fail(w, 401, "invalid setup token")
				return true
			}
			if e = validateName(b.Username); e != nil || len(b.Password) < 12 || len(b.Password) > 1024 {
				fail(w, 400, "username must be 1–80 characters and password 12–1024 bytes")
				return true
			}
			salt := randomBytes(16)
			hash := passwordHash(b.Password, salt)
			tx, e := a.store.db.Begin()
			if e != nil {
				fail(w, 500, "cannot initialize administrator")
				return true
			}
			defer tx.Rollback()
			if _, e = tx.Exec("INSERT INTO admin VALUES(1,?,?,?)", b.Username, salt, hash); e == nil {
				e = auditTx(tx, "admin.setup", b.Username)
			}
			if e == nil {
				e = tx.Commit()
			}
			if e != nil {
				fail(w, 500, "cannot initialize administrator")
				return true
			}
			os.Remove(filepath.Join(a.store.dir, "bootstrap-token"))
		} else {
			var username string
			var salt, hash []byte
			e := a.store.db.QueryRow("SELECT username,salt,hash FROM admin WHERE id=1").Scan(&username, &salt, &hash)
			if len(b.Password) > 1024 {
				fail(w, 401, "invalid username or password")
				return true
			}
			if e != nil {
				salt = make([]byte, 16)
				hash = make([]byte, 32)
			}
			match := equal(passwordHash(b.Password, salt), hash)
			if e != nil || username != b.Username || !match {
				fail(w, 401, "invalid username or password")
				return true
			}
		}
		s, e := a.newSession(w, b.Username, "")
		if e != nil {
			fail(w, 500, "cannot create session")
		} else {
			respond(w, 200, map[string]string{"username": s.Username, "csrfToken": s.CSRF})
		}
		return true
	case path == "/api/session" && r.Method == "GET":
		s, e := a.session(r)
		if e != nil && fnos {
			s, e = a.newSession(w, r.Header.Get("X-Trim-Username"), r.Header.Get("X-Trim-Userid"))
		}
		if e != nil {
			fail(w, 401, "authentication required")
		} else {
			respond(w, 200, map[string]string{"username": s.Username, "csrfToken": s.CSRF})
		}
		return true
	}
	s, e := a.session(r)
	if e != nil {
		fail(w, 401, "authentication required")
		return true
	}
	if r.Method != "GET" && r.Method != "HEAD" && !equal([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) {
		fail(w, 403, "invalid CSRF token")
		return true
	}
	if path == "/api/logout" && r.Method == "POST" {
		if c, e := r.Cookie(a.cookieName()); e == nil {
			a.store.db.Exec("DELETE FROM sessions WHERE hash=?", digest(c.Value))
		}
		a.cookie(w, "", time.Unix(1, 0))
		respond(w, 200, map[string]bool{"ok": true})
		return true
	}
	return false
}
func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 64*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("invalid JSON request")
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}
