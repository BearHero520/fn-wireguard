package app

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type parsedConfig struct {
	Interface map[string]string
	Peers     []map[string]string
}

// parseConfig accepts the declarative WireGuard subset supported by the app.
// It never executes wg-quick hooks or silently discards unknown configuration.
func parseConfig(raw string) (parsedConfig, error) {
	out := parsedConfig{}
	if len(raw) > 64*1024 {
		return out, errors.New("configuration exceeds 64 KiB")
	}
	var section map[string]string
	for n, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch line {
			case "[Interface]":
				if out.Interface != nil || len(out.Peers) > 0 {
					return out, fmt.Errorf("line %d: duplicate or misplaced Interface section", n+1)
				}
				out.Interface = map[string]string{}
				section = out.Interface
			case "[Peer]":
				if out.Interface == nil {
					return out, errors.New("Interface must precede Peer sections")
				}
				if len(out.Peers) >= 253 {
					return out, errors.New("too many peers")
				}
				section = map[string]string{}
				out.Peers = append(out.Peers, section)
			default:
				return out, fmt.Errorf("line %d: unsupported section", n+1)
			}
			continue
		}
		if section == nil {
			return out, fmt.Errorf("line %d: field outside section", n+1)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return out, fmt.Errorf("line %d: expected key = value", n+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			return out, fmt.Errorf("line %d: empty field", n+1)
		}
		for _, c := range value {
			if c < 32 || c == 127 {
				return out, fmt.Errorf("line %d: control character in value", n+1)
			}
		}
		if _, ok = section[key]; ok {
			return out, fmt.Errorf("line %d: duplicate field %s", n+1, key)
		}
		isInterface := len(out.Peers) == 0
		allowed := false
		if isInterface {
			switch key {
			case "privatekey", "address", "listenport", "dns":
				allowed = true
			}
		} else {
			switch key {
			case "publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive":
				allowed = true
			}
		}
		if !allowed {
			return out, fmt.Errorf("line %d: unsupported field %s (hooks and routing commands are forbidden)", n+1, key)
		}
		switch key {
		case "privatekey", "publickey", "presharedkey":
			k, e := wgtypes.ParseKey(value)
			if e != nil || k == (wgtypes.Key{}) {
				return out, fmt.Errorf("line %d: invalid %s", n+1, key)
			}
		case "listenport":
			p, e := strconv.Atoi(value)
			if e != nil || p < 1 || p > 65535 {
				return out, errors.New("invalid listen port")
			}
		case "persistentkeepalive":
			p, e := strconv.Atoi(value)
			if e != nil || p < 0 || p > 65535 {
				return out, errors.New("invalid keepalive")
			}
		case "allowedips", "address":
			for _, v := range strings.Split(value, ",") {
				if _, e := netip.ParsePrefix(strings.TrimSpace(v)); e != nil {
					return out, fmt.Errorf("line %d: invalid CIDR", n+1)
				}
			}
		case "dns":
			for _, v := range strings.Split(value, ",") {
				if _, e := netip.ParseAddr(strings.TrimSpace(v)); e != nil {
					return out, errors.New("DNS must contain IP addresses")
				}
			}
		}
		section[key] = value
	}
	if out.Interface == nil || out.Interface["privatekey"] == "" || out.Interface["address"] == "" {
		return out, errors.New("Interface requires PrivateKey and Address")
	}
	seen := map[string]bool{}
	for _, p := range out.Peers {
		if p["publickey"] == "" || p["allowedips"] == "" {
			return out, errors.New("each Peer requires PublicKey and AllowedIPs")
		}
		if seen[p["publickey"]] {
			return out, errors.New("duplicate peer public key")
		}
		seen[p["publickey"]] = true
	}
	return out, nil
}

func serverConfig(s Settings, private string, peers []runtimePeer) (string, error) {
	if e := validateSettings(s); e != nil {
		return "", e
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n", private, s.Address, s.ListenPort)
	for _, p := range peers {
		if p.Enabled {
			fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", p.PublicKey)
			if p.PSK != "" {
				fmt.Fprintf(&b, "PresharedKey = %s\n", p.PSK)
			}
			fmt.Fprintf(&b, "AllowedIPs = %s\n", p.Address)
		}
	}
	return b.String(), nil
}

func (a *App) exportServerConfig(w http.ResponseWriter, r *http.Request) {
	s, private, _, e := a.store.settings()
	if e != nil {
		fail(w, 500, "cannot read server settings")
		return
	}
	peers, e := a.store.peers()
	if e != nil {
		fail(w, 500, "cannot read peers")
		return
	}
	config, e := serverConfig(s, private, peers)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	tx, e := a.store.db.Begin()
	if e == nil {
		e = auditTx(tx, "server.config.export", iface)
		if e == nil {
			e = tx.Commit()
		} else {
			tx.Rollback()
		}
	}
	if e != nil {
		fail(w, 500, "cannot record server configuration export")
		return
	}
	respond(w, 200, map[string]string{"filename": "fnwg0.conf", "config": config})
}
