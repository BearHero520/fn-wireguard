package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
)

type Store struct {
	db  *sql.DB
	key []byte
	dir string
}

func OpenStore(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if e := os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	key, e := masterKey(dir)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, "state.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, key: key, dir: dir}
	if _, e = db.Exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL,private BLOB NOT NULL,public TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT NOT NULL,salt BLOB NOT NULL,hash BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS peers(id TEXT PRIMARY KEY,name TEXT NOT NULL,device TEXT NOT NULL,address TEXT UNIQUE NOT NULL,public TEXT UNIQUE NOT NULL,private BLOB NOT NULL,psk BLOB NOT NULL,enabled INTEGER NOT NULL,created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer_access(peer_id TEXT PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE, mode TEXT NOT NULL, targets TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,username TEXT NOT NULL,uid TEXT NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS lifecycle(id INTEGER PRIMARY KEY CHECK(id=1),desired INTEGER NOT NULL); INSERT OR IGNORE INTO lifecycle VALUES(1,0);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT NOT NULL,target TEXT NOT NULL,created TEXT NOT NULL);`); e != nil {
		db.Close()
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		db.Close()
		return nil, e
	}
	var count int
	if e = db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count); e != nil {
		return nil, e
	}
	if count == 0 {
		priv, pub, e := privateKey()
		if e != nil {
			return nil, e
		}
		enc, e := encrypt(key, priv, "server")
		if e != nil {
			return nil, e
		}
		j, _ := json.Marshal(defaultSettings())
		if _, e = db.Exec("INSERT INTO settings VALUES(1,?,?,?)", string(j), enc, pub); e != nil {
			return nil, e
		}
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) settings() (Settings, string, string, error) {
	var j, pub string
	var enc []byte
	var v Settings
	e := s.db.QueryRow("SELECT value,private,public FROM settings WHERE id=1").Scan(&j, &enc, &pub)
	if e != nil {
		return v, "", "", e
	}
	if e = json.Unmarshal([]byte(j), &v); e != nil {
		return v, "", "", e
	}
	priv, e := decrypt(s.key, enc, "server")
	return v, priv, pub, e
}
func (s *Store) peers() ([]runtimePeer, error) {
	rows, e := s.db.Query("SELECT p.id,p.name,p.device,p.address,p.public,p.private,p.psk,p.enabled,p.created,COALESCE(a.mode,'inherit'),COALESCE(a.targets,'[]') FROM peers p LEFT JOIN peer_access a ON p.id=a.peer_id ORDER BY p.created,p.id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []runtimePeer{}
	for rows.Next() {
		var p runtimePeer
		var enc, psk []byte
		var targets string
		if e = rows.Scan(&p.ID, &p.Name, &p.DeviceType, &p.Address, &p.PublicKey, &enc, &psk, &p.Enabled, &p.CreatedAt, &p.AccessMode, &targets); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(targets), &p.AllowedDevices); e != nil {
			return nil, e
		}
		p.Private, e = decrypt(s.key, enc, "peer:"+p.ID)
		if e != nil {
			return nil, e
		}
		p.HasConfig = p.Private != ""
		p.PSK, e = decrypt(s.key, psk, "psk:"+p.ID)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Store) insertPeer(tx *sql.Tx, p runtimePeer) error {
	priv, e := encrypt(s.key, p.Private, "peer:"+p.ID)
	if e != nil {
		return e
	}
	psk, e := encrypt(s.key, p.PSK, "psk:"+p.ID)
	if e != nil {
		return e
	}
	_, e = tx.Exec("INSERT INTO peers VALUES(?,?,?,?,?,?,?,?,?)", p.ID, p.Name, p.DeviceType, p.Address, p.PublicKey, priv, psk, p.Enabled, p.CreatedAt)
	return e
}
func auditTx(tx *sql.Tx, action, target string) error {
	_, e := tx.Exec("INSERT INTO audit(action,target,created) VALUES(?,?,?)", action, target, now())
	if e == nil {
		_, e = tx.Exec("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 1000)")
	}
	return e
}
func (s *Store) audits() ([]Audit, error) {
	rows, e := s.db.Query("SELECT CAST(id AS TEXT),action,target,created FROM audit ORDER BY id DESC LIMIT 50")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var a Audit
		if e = rows.Scan(&a.ID, &a.Action, &a.Target, &a.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) initialized() (bool, error) {
	var n int
	e := s.db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&n)
	return n > 0, e
}
func (s *Store) bootstrap() error {
	yes, e := s.initialized()
	if e != nil || yes {
		return e
	}
	p := filepath.Join(s.dir, "bootstrap-token")
	if _, e = os.Stat(p); e == nil {
		return os.Chmod(p, 0600)
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.WriteString(token() + "\n")
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

var errNotFound = errors.New("peer not found")

func writePeerAccess(tx *sql.Tx, p Peer) error {
	mode := p.AccessMode
	if mode == "" {
		mode = "inherit"
	}
	targets := p.AllowedDevices
	if targets == nil {
		targets = []string{}
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO peer_access(peer_id,mode,targets) VALUES(?,?,?) ON CONFLICT(peer_id) DO UPDATE SET mode=excluded.mode,targets=excluded.targets", p.ID, mode, string(encoded))
	return err
}
