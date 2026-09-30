package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type importRequest struct {
	Kind       string `json:"kind"`
	Config     string `json:"config"`
	Name       string `json:"name"`
	DeviceType string `json:"deviceType"`
}
type importSummary struct {
	Address    string `json:"address"`
	ListenPort int    `json:"listenPort"`
	PeerCount  int    `json:"peerCount"`
	PublicKey  string `json:"publicKey"`
	Operation  string `json:"operation"`
	Name       string `json:"name"`
	CanExport  bool   `json:"canExport"`
}
type importPlan struct {
	Request         importRequest
	Owner, Snapshot string
	Expires         time.Time
	Settings        Settings
	Private, Public string
	Peers           []runtimePeer
	Summary         importSummary
	Warnings        []string
}

func snapshot(s Settings, pub string, peers []runtimePeer) string {
	b, _ := json.Marshal(struct {
		Settings Settings
		Public   string
		Peers    []runtimePeer
	}{s, pub, peers})
	return digest(string(b))
}
func (a *App) importOwner(r *http.Request) string {
	c, e := r.Cookie(a.cookieName())
	if e != nil {
		return ""
	}
	return digest(c.Value) + ":" + r.Header.Get("X-Trim-Userid")
}
func peerAddress(raw string, s Settings, strict bool) (string, error) {
	if strings.Contains(raw, ",") {
		return "", errors.New("peer must have exactly one IPv4 address")
	}
	p, e := netip.ParsePrefix(strings.TrimSpace(raw))
	if e != nil || !p.Addr().Is4() {
		return "", errors.New("peer must have exactly one IPv4 CIDR address")
	}
	if strict && p.Bits() != 32 {
		return "", errors.New("server peer AllowedIPs must be one /32 host route; broad or IPv6 routes are unsupported")
	}
	network, e := serverPrefix(s.Address)
	if e != nil {
		return "", e
	}
	ip := p.Addr()
	if !network.Contains(ip) || ip == network.Addr() || ip == network.Masked().Addr() || ip == lastAddress(network) {
		return "", errors.New("peer address must be an unused host inside the NAS tunnel subnet")
	}
	return ip.String() + "/32", nil
}
func (a *App) planImport(b importRequest) (importPlan, error) {
	plan := importPlan{Request: b, Expires: time.Now().Add(5 * time.Minute), Warnings: []string{}}
	if a.options.Mode == "production" && a.runtimeError != "" {
		return plan, errors.New("runtime state is unresolved; successfully stop or restart the server before importing")
	}
	if len(b.Config) > 32*1024 {
		return plan, errors.New("configuration exceeds 32 KiB")
	}
	parsed, e := parseConfig(b.Config)
	if e != nil {
		return plan, e
	}
	s, priv, pub, e := a.store.settings()
	if e != nil {
		return plan, e
	}
	peers, e := a.store.peers()
	if e != nil {
		return plan, e
	}
	plan.Snapshot = snapshot(s, pub, peers)
	plan.Settings = s
	plan.Private = priv
	plan.Public = pub
	plan.Peers = append([]runtimePeer{}, peers...)
	status := a.adapter.Status()
	if a.options.Mode == "production" && (!status.Available || status.Reason != "") {
		return plan, errors.New("runtime state is uncertain; resolve the server error before importing")
	}
	switch b.Kind {
	case "server":
		if status.Running {
			return plan, errors.New("stop the server before importing a server configuration")
		}
		if len(peers) > 0 {
			return plan, errors.New("server import requires an empty peer list; existing devices will not be overwritten")
		}
		if strings.Contains(parsed.Interface["address"], ",") {
			return plan, errors.New("server Interface must have one private IPv4 address")
		}
		if _, e = serverPrefix(parsed.Interface["address"]); e != nil {
			return plan, e
		}
		if parsed.Interface["listenport"] == "" {
			return plan, errors.New("server Interface requires ListenPort")
		}
		s.Address = parsed.Interface["address"]
		s.ListenPort, _ = strconv.Atoi(parsed.Interface["listenport"])
		if dns := parsed.Interface["dns"]; dns != "" {
			s.DNS = dns
		}
		prefix, _ := serverPrefix(s.Address)
		s.AllowedIPs = prefix.Masked().String()
		if managedAccess(s) {
			s, e = a.prepareAccess(s)
			if e != nil {
				return plan, e
			}
		}
		if e = validateSettings(s); e != nil {
			return plan, e
		}
		priv = parsed.Interface["privatekey"]
		pub, e = publicKey(priv)
		if e != nil {
			return plan, errors.New("invalid server private key")
		}
		seen := map[string]bool{}
		newPeers := []runtimePeer{}
		for i, p := range parsed.Peers {
			if p["endpoint"] != "" || p["persistentkeepalive"] != "" {
				return plan, errors.New("server Peer Endpoint and PersistentKeepalive are unsupported; import client configuration separately")
			}
			if p["publickey"] == pub {
				return plan, errors.New("peer public key cannot equal the server public key")
			}
			address, e := peerAddress(p["allowedips"], s, true)
			if e != nil {
				return plan, e
			}
			if seen[address] {
				return plan, errors.New("duplicate peer address")
			}
			seen[address] = true
			newPeers = append(newPeers, runtimePeer{Peer: Peer{ID: token(), Name: fmt.Sprintf("导入设备 %d", i+1), DeviceType: "other", Address: address, PublicKey: p["publickey"], Enabled: true, CreatedAt: now()}, PSK: p["presharedkey"]})
		}
		plan.Settings = s
		plan.Private = priv
		plan.Public = pub
		plan.Peers = newPeers
		plan.Summary = importSummary{Address: s.Address, ListenPort: s.ListenPort, PeerCount: len(newPeers), PublicKey: pub, Operation: "replace-server", Name: "WireGuard server", CanExport: false}
		plan.Warnings = append(plan.Warnings, "Server private key and tunnel settings will be replaced. Existing public endpoint is preserved.", "Imported peers contain public keys only. Import each original client configuration to enable its QR code and client export.", "LAN access settings are preserved when enabled. Otherwise client routes reset to the imported tunnel subnet. Access permissions are not included in WireGuard configuration files.")
		if s.Endpoint == "" {
			plan.Warnings = append(plan.Warnings, "Save the public endpoint in settings before exporting client configurations.")
		}
	case "client":
		if parsed.Interface["listenport"] != "" {
			return plan, errors.New("client Interface ListenPort is unsupported")
		}
		if len(parsed.Peers) != 1 {
			return plan, errors.New("client configuration must contain exactly one server Peer")
		}
		remote := parsed.Peers[0]
		if remote["publickey"] != pub {
			return plan, errors.New("client configuration belongs to a different WireGuard server")
		}
		address, e := peerAddress(parsed.Interface["address"], s, false)
		if e != nil {
			return plan, e
		}
		if address != parsed.Interface["address"] {
			plan.Warnings = append(plan.Warnings, "Client address will be normalized to a /32 host address.")
		}
		check := s
		check.Endpoint = remote["endpoint"]
		if check.Endpoint == "" {
			return plan, errors.New("client server Peer requires Endpoint")
		}
		check.AllowedIPs = remote["allowedips"]
		if dns := parsed.Interface["dns"]; dns != "" {
			check.DNS = dns
		}
		if keepalive := remote["persistentkeepalive"]; keepalive != "" {
			check.PersistentKeepalive, _ = strconv.Atoi(keepalive)
		}
		if e = validateSettings(check); e != nil {
			return plan, e
		}
		clientPrivate := parsed.Interface["privatekey"]
		clientPub, e := publicKey(clientPrivate)
		if e != nil {
			return plan, errors.New("invalid client private key")
		}
		if clientPub == pub {
			return plan, errors.New("client key cannot equal the server key")
		}
		if b.Name == "" {
			b.Name = "导入客户端"
		}
		if e = validateName(b.Name); e != nil {
			return plan, e
		}
		if b.DeviceType == "" {
			b.DeviceType = "other"
		}
		switch b.DeviceType {
		case "phone", "computer", "tablet", "other":
		default:
			return plan, errors.New("invalid device type")
		}
		index := -1
		for i, p := range peers {
			if p.PublicKey == clientPub {
				index = i
				break
			}
			if p.Address == address {
				return plan, errors.New("client address is already assigned to another peer")
			}
		}
		operation := "create-peer"
		var p runtimePeer
		if index >= 0 {
			p = peers[index]
			if p.Private != "" {
				return plan, errors.New("client is already managed and has a private key")
			}
			if p.Address != address || p.PSK != remote["presharedkey"] {
				return plan, errors.New("client address or preshared key does not match the imported server peer")
			}
			p.Private = clientPrivate
			p.HasConfig = true
			plan.Peers[index] = p
			operation = "complete-peer"
		} else {
			p = runtimePeer{Peer: Peer{ID: token(), Name: strings.TrimSpace(b.Name), DeviceType: b.DeviceType, Address: address, PublicKey: clientPub, Enabled: true, HasConfig: true, CreatedAt: now()}, Private: clientPrivate, PSK: remote["presharedkey"]}
			plan.Peers = append(plan.Peers, p)
		}
		plan.Summary = importSummary{Address: address, ListenPort: s.ListenPort, PeerCount: 1, PublicKey: pub, Operation: operation, Name: p.Name, CanExport: true}
		plan.Warnings = append(plan.Warnings, "Client endpoint, DNS, routes, and keepalive are validated but do not change NAS settings. Future exports use the NAS settings.")
	default:
		return plan, errors.New("kind must be server or client")
	}
	return plan, nil
}
func (a *App) previewImport(w http.ResponseWriter, r *http.Request) {
	var b importRequest
	if e := decode(r, &b); e != nil {
		fail(w, 400, e.Error())
		return
	}
	plan, e := a.planImport(b)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	for k, p := range a.imports {
		if time.Now().After(p.Expires) {
			delete(a.imports, k)
		}
	}
	if len(a.imports) >= 16 {
		fail(w, 429, "too many pending import previews; wait five minutes")
		return
	}
	key := token()
	plan.Owner = a.importOwner(r)
	a.imports[key] = plan
	respond(w, 200, map[string]any{"previewToken": key, "kind": b.Kind, "summary": plan.Summary, "warnings": plan.Warnings})
}
func (a *App) applyImport(w http.ResponseWriter, r *http.Request) {
	var b struct {
		PreviewToken string `json:"previewToken"`
	}
	if e := decode(r, &b); e != nil {
		fail(w, 400, e.Error())
		return
	}
	plan, ok := a.imports[b.PreviewToken]
	if !ok || plan.Owner != a.importOwner(r) {
		fail(w, 400, "invalid import preview token")
		return
	}
	delete(a.imports, b.PreviewToken)
	if time.Now().After(plan.Expires) {
		fail(w, 409, "import preview expired; preview again")
		return
	}
	fresh, e := a.planImport(plan.Request)
	if e != nil {
		fail(w, 409, e.Error())
		return
	}
	if fresh.Snapshot != plan.Snapshot {
		fail(w, 409, "server or peers changed after preview; preview again")
		return
	}
	old, e := a.store.peers()
	if e != nil {
		fail(w, 500, "cannot read peers")
		return
	}
	changed := false
	if plan.Request.Kind == "client" {
		changed, e = a.mutateRuntime(old, plan.Peers)
		if e != nil {
			fail(w, 503, e.Error())
			return
		}
	}
	tx, e := a.store.db.Begin()
	if e != nil {
		if changed {
			a.rollbackRuntime(old)
		}
		fail(w, 500, "cannot start import transaction")
		return
	}
	defer tx.Rollback()
	if plan.Request.Kind == "server" {
		j, _ := json.Marshal(plan.Settings)
		enc, ee := encrypt(a.store.key, plan.Private, "server")
		if ee != nil {
			e = ee
		} else {
			_, e = tx.Exec("UPDATE settings SET value=?,private=?,public=? WHERE id=1", string(j), enc, plan.Public)
		}
		if e == nil {
			_, e = tx.Exec("UPDATE lifecycle SET desired=0 WHERE id=1")
		}
		if e == nil {
			for _, p := range plan.Peers {
				if e = a.store.insertPeer(tx, p); e != nil {
					break
				}
			}
		}
	} else {
		for _, p := range plan.Peers {
			if p.Private == "" {
				continue
			}
			found := false
			for _, before := range old {
				if before.ID == p.ID {
					found = true
					if before.Private == "" && p.Private != "" {
						enc, ee := encrypt(a.store.key, p.Private, "peer:"+p.ID)
						if ee != nil {
							e = ee
						} else {
							_, e = tx.Exec("UPDATE peers SET private=? WHERE id=?", enc, p.ID)
						}
					}
					break
				}
			}
			if !found {
				e = a.store.insertPeer(tx, p)
			}
			if e != nil {
				break
			}
		}
	}
	if e == nil {
		e = auditTx(tx, "config.import."+plan.Request.Kind, plan.Summary.Name)
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		tx.Rollback()
		if changed {
			a.rollbackRuntime(old)
		}
		fail(w, 500, "cannot save imported configuration")
		return
	}
	a.runtimeError = ""
	response := map[string]any{"ok": true, "kind": plan.Request.Kind}
	if plan.Request.Kind == "client" {
		for _, p := range plan.Peers {
			if p.Name == plan.Summary.Name && p.Address == plan.Summary.Address {
				response["peer"] = p.Peer
				break
			}
		}
	}
	respond(w, 200, response)
}
