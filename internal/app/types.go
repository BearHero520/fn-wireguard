package app

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Settings struct {
	Endpoint            string   `json:"endpoint"`
	ListenPort          int      `json:"listenPort"`
	Address             string   `json:"address"`
	DNS                 string   `json:"dns"`
	AllowedIPs          string   `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive"`
	AccessMode          string   `json:"accessMode,omitempty"`
	LANSubnet           string   `json:"lanSubnet,omitempty"`
	LANAddress          string   `json:"lanAddress,omitempty"`
	LANInterface        string   `json:"lanInterface,omitempty"`
	AllowedDevices      []string `json:"allowedDevices,omitempty"`
}
type Peer struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	DeviceType     string   `json:"deviceType"`
	Address        string   `json:"address"`
	PublicKey      string   `json:"publicKey"`
	Enabled        bool     `json:"enabled"`
	CreatedAt      string   `json:"createdAt"`
	LastHandshake  *string  `json:"lastHandshake"`
	ReceivedBytes  uint64   `json:"receivedBytes"`
	SentBytes      uint64   `json:"sentBytes"`
	Online         bool     `json:"online"`
	HasConfig      bool     `json:"hasConfig"`
	AccessMode     string   `json:"accessMode,omitempty"`
	AllowedDevices []string `json:"allowedDevices,omitempty"`
}
type Audit struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	CreatedAt string `json:"createdAt"`
}
type runtimePeer struct {
	Peer
	Private string
	PSK     string
}
type RuntimeStatus struct {
	Running    bool
	ListenPort int
	Available  bool
	Reason     string
	Peers      map[string]Counters
}
type Counters struct {
	Handshake int64
	RX, TX    uint64
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
func defaultSettings() Settings {
	return Settings{ListenPort: 51820, Address: "10.66.66.1/24", DNS: "", AllowedIPs: "10.66.66.0/24", PersistentKeepalive: 25}
}

// A host without a port uses the configured WireGuard listening port. Keep
// malformed input intact so validation can report it instead of guessing.
func normalizeSettings(s Settings) Settings {
	s.Endpoint = strings.Trim(s.Endpoint, " ")
	if s.Endpoint == "" {
		return s
	}
	host := s.Endpoint
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if _, err := netip.ParseAddr(host); err == nil || !strings.ContainsAny(s.Endpoint, ":[]") {
		s.Endpoint = net.JoinHostPort(host, strconv.Itoa(s.ListenPort))
	}
	return s
}
func validateName(s string) error {
	if len(strings.TrimSpace(s)) < 1 || len(s) > 80 {
		return errors.New("name must be 1–80 characters")
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return errors.New("name contains control characters")
		}
	}
	return nil
}
func serverPrefix(s string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(s)
	if e != nil || !p.Addr().Is4() || p.Bits() < 24 || p.Bits() > 30 || !p.Addr().IsPrivate() {
		return p, errors.New("server address must use a private IPv4 /24–/30 subnet")
	}
	base := p.Masked().Addr()
	last := lastAddress(p)
	if p.Addr() == base || p.Addr() == last {
		return p, errors.New("server address cannot be network or broadcast address")
	}
	return p, nil
}
func lastAddress(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= uint32(1)<<(32-p.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
func validateSettings(s Settings) error {
	for _, v := range []string{s.Endpoint, s.Address, s.DNS, s.AllowedIPs} {
		for _, c := range v {
			if c < 32 || c == 127 {
				return errors.New("configuration fields cannot contain control characters")
			}
		}
	}
	if _, e := serverPrefix(s.Address); e != nil {
		return e
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 {
		return errors.New("listen port must be 1–65535")
	}
	if s.PersistentKeepalive < 0 || s.PersistentKeepalive > 65535 {
		return errors.New("keepalive must be 0–65535")
	}
	if len(s.Endpoint) > 253 {
		return errors.New("endpoint too long")
	}
	if s.Endpoint != "" {
		if strings.ContainsAny(s.Endpoint, "/\\") {
			return errors.New("endpoint must be hostname:port or [IPv6]:port")
		}
		h, p, e := net.SplitHostPort(s.Endpoint)
		if e != nil {
			return errors.New("endpoint must be hostname:port or [IPv6]:port")
		}
		port, e := strconv.Atoi(p)
		if e != nil || port < 1 || port > 65535 {
			return errors.New("invalid endpoint port")
		}
		if _, e := netip.ParseAddr(h); e != nil {
			if len(h) == 0 || strings.ContainsAny(h, "\r\n /\\#;\t") {
				return errors.New("invalid endpoint host")
			}
			for _, label := range strings.Split(h, ".") {
				if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
					return errors.New("invalid endpoint hostname")
				}
				for _, c := range label {
					if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
						return errors.New("invalid endpoint hostname")
					}
				}
			}
		}
	}
	// Empty DNS means that clients keep their current network's resolver.
	if s.DNS != "" {
		for _, d := range strings.Split(s.DNS, ",") {
			if _, e := netip.ParseAddr(strings.TrimSpace(d)); e != nil {
				return errors.New("DNS must be comma-separated IP addresses")
			}
		}
	}
	if len(s.DNS) > 512 || len(s.AllowedIPs) > 4096 {
		return errors.New("too many DNS or routing entries")
	}
	for _, v := range strings.Split(s.AllowedIPs, ",") {
		if _, e := netip.ParsePrefix(strings.TrimSpace(v)); e != nil {
			return errors.New("allowed IPs must be comma-separated CIDRs")
		}
	}
	return nil
}
func allocate(address string, peers []runtimePeer) (string, error) {
	p, e := serverPrefix(address)
	if e != nil {
		return "", e
	}
	used := map[netip.Addr]bool{p.Addr(): true}
	for _, v := range peers {
		a, e := netip.ParseAddr(strings.Split(v.Address, "/")[0])
		if e != nil {
			return "", e
		}
		used[a] = true
	}
	for a := p.Masked().Addr().Next(); a != lastAddress(p); a = a.Next() {
		if !used[a] {
			return fmt.Sprintf("%s/32", a), nil
		}
	}
	return "", errors.New("subnet has no available peer addresses")
}
