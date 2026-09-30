package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"time"
)

const iface = "fnwg0"
const ownership = "fn-wireguard-managed-v1"

// Used only when Apply failed before attempting any runtime mutation.
type runtimeUnchangedError struct{ error }

func (e *runtimeUnchangedError) Unwrap() error { return e.error }

type Adapter interface {
	Status() RuntimeStatus
	Apply(Settings, string, []runtimePeer) error
	Start(Settings, string, []runtimePeer) error
	Stop() error
}
type LinuxAdapter struct {
	ip     string
	reason string
}

func NewAdapter(mode string) Adapter {
	a := &LinuxAdapter{}
	if mode != "production" {
		a.reason = "Development mode: WireGuard runtime is unavailable"
		return a
	}
	if runtime.GOOS != "linux" {
		a.reason = "WireGuard runtime requires Linux"
		return a
	}
	var e error
	a.ip, e = exec.LookPath("ip")
	if e != nil {
		a.reason = "Required ip binary is missing"
	}
	return a
}
func (a *LinuxAdapter) command(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, a.ip, args...)
	var out bytes.Buffer
	c.Stdout = &out
	if e := c.Run(); e != nil {
		return nil, fmt.Errorf("ip operation failed: %w (check NET_ADMIN capability and kernel WireGuard support)", e)
	}
	return out.Bytes(), nil
}
func (a *LinuxAdapter) linkState() (bool, bool, error) {
	b, e := a.command("-json", "link", "show")
	if e != nil {
		return false, false, e
	}
	return ownedLinkState(b)
}
func ownedLinkState(data []byte) (bool, bool, error) {
	var links []struct {
		IfName string
		Alias  string `json:"ifalias"`
		Flags  []string
	}
	if e := json.Unmarshal(data, &links); e != nil {
		return false, false, e
	}
	for _, link := range links {
		if link.IfName != iface {
			continue
		}
		if link.Alias != ownership {
			return false, false, errors.New("fnwg0 exists without application ownership; refusing to modify it")
		}
		for _, flag := range link.Flags {
			if flag == "UP" {
				return true, true, nil
			}
		}
		return true, false, nil
	}
	return false, false, nil
}
func (a *LinuxAdapter) exists() (bool, error) {
	exists, _, err := a.linkState()
	return exists, err
}
func (a *LinuxAdapter) Status() RuntimeStatus {
	s := RuntimeStatus{Peers: map[string]Counters{}, Available: a.reason == "", Reason: a.reason}
	if a.reason != "" {
		return s
	}
	yes, up, e := a.linkState()
	if e != nil {
		s.Reason = e.Error()
		s.Available = false
		return s
	}
	if !yes || !up {
		return s
	}
	c, e := wgctrl.New()
	if e != nil {
		s.Reason = "cannot open WireGuard control: " + e.Error()
		return s
	}
	defer c.Close()
	d, e := c.Device(iface)
	if e != nil {
		s.Reason = "cannot read WireGuard device: " + e.Error()
		return s
	}
	s.Running = true
	s.ListenPort = d.ListenPort
	for _, p := range d.Peers {
		h := int64(0)
		if !p.LastHandshakeTime.IsZero() {
			h = p.LastHandshakeTime.Unix()
		}
		s.Peers[p.PublicKey.String()] = Counters{h, uint64(p.ReceiveBytes), uint64(p.TransmitBytes)}
	}
	return s
}
func (a *LinuxAdapter) Apply(s Settings, private string, peers []runtimePeer) error {
	if a.reason != "" {
		return errors.New(a.reason)
	}
	yes, e := a.exists()
	if e != nil {
		return e
	}
	if !yes {
		return errors.New("WireGuard interface is missing")
	}
	key, e := wgtypes.ParseKey(private)
	if e != nil {
		return errors.New("invalid server key")
	}
	cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &s.ListenPort, ReplacePeers: true}
	for _, p := range peers {
		if !p.Enabled {
			continue
		}
		pub, e := wgtypes.ParseKey(p.PublicKey)
		if e != nil {
			return errors.New("invalid peer key")
		}
		var psk *wgtypes.Key
		if p.PSK != "" {
			k, err := wgtypes.ParseKey(p.PSK)
			if err != nil {
				return errors.New("invalid preshared key")
			}
			psk = &k
		}
		_, cidr, e := net.ParseCIDR(p.Address)
		if e != nil {
			return e
		}
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: pub, PresharedKey: psk, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*cidr}})
	}
	if e = applyFirewall(s, peers); e != nil {
		return e
	}
	c, e := wgctrl.New()
	if e != nil {
		return e
	}
	defer c.Close()
	if e = c.ConfigureDevice(iface, cfg); e != nil {
		if portInUse(e) {
			return fmt.Errorf("UDP port %d is already in use", s.ListenPort)
		}
		return fmt.Errorf("WireGuard configuration failed: %w", e)
	}
	d, e := c.Device(iface)
	if e != nil {
		return fmt.Errorf("cannot verify WireGuard listening port: %w", e)
	}
	if d.ListenPort != s.ListenPort {
		return fmt.Errorf("WireGuard listening port mismatch: expected %d, actual %d", s.ListenPort, d.ListenPort)
	}
	return nil
}
func (a *LinuxAdapter) Start(s Settings, private string, peers []runtimePeer) error {
	if a.reason != "" {
		return errors.New(a.reason)
	}
	if e := validateSettings(s); e != nil {
		return e
	}
	yes, e := a.exists()
	if e != nil {
		return e
	}
	addresses, e := a.command("-json", "address", "show")
	if e != nil {
		return e
	}
	if e = checkOverlap(s.Address, addresses); e != nil {
		return e
	}
	if yes {
		if _, e = a.command("link", "set", "dev", iface, "down"); e != nil {
			return e
		}
		if e = a.Apply(s, private, peers); e != nil {
			return e
		}
		if _, e = a.command("address", "replace", s.Address, "dev", iface); e != nil {
			return e
		}
		_, e = a.command("link", "set", "dev", iface, "up")
		return e
	}
	if _, e = a.command("link", "add", "dev", iface, "type", "wireguard"); e != nil {
		return e
	}
	if _, e = a.command("link", "set", "dev", iface, "alias", ownership); e != nil {
		a.command("link", "delete", "dev", iface)
		return e
	}
	cleanup := func() {
		if ce := a.Stop(); ce != nil {
			e = fmt.Errorf("%v; cleanup failed: %v", e, ce)
		}
	}
	if e = a.Apply(s, private, peers); e != nil {
		cleanup()
		return e
	}
	if _, e = a.command("address", "add", s.Address, "dev", iface); e != nil {
		cleanup()
		return e
	}
	if _, e = a.command("link", "set", "dev", iface, "up"); e != nil {
		cleanup()
		return e
	}
	return nil
}
func checkOverlap(address string, data []byte) error {
	tunnel, e := serverPrefix(address)
	if e != nil {
		return e
	}
	var devices []struct {
		IfName    string `json:"ifname"`
		Addresses []struct {
			Family, Local string
			PrefixLen     int `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if e = json.Unmarshal(data, &devices); e != nil {
		return e
	}
	for _, d := range devices {
		if d.IfName == iface {
			continue
		}
		for _, a := range d.Addresses {
			if a.Family != "inet" {
				continue
			}
			ip, e := netip.ParseAddr(a.Local)
			if e != nil || !ip.Is4() || a.PrefixLen < 0 || a.PrefixLen > 32 {
				return errors.New("invalid system IPv4 address data")
			}
			p := netip.PrefixFrom(ip, a.PrefixLen)
			if tunnel.Overlaps(p) {
				return fmt.Errorf("tunnel subnet overlaps interface %s; choose another private subnet", d.IfName)
			}
		}
	}
	return nil
}
func (a *LinuxAdapter) Stop() error {
	if a.reason != "" {
		return errors.New(a.reason)
	}
	yes, e := a.exists()
	if e != nil {
		return e
	}
	if yes {
		if _, e = a.command("link", "delete", "dev", iface); e != nil {
			return e
		}
	}
	return applyFirewall(Settings{}, nil)
}
func clientConfig(s Settings, p runtimePeer, serverPublic string) (string, error) {
	if p.Private == "" {
		return "", errors.New("This imported peer has no private key; import its client configuration to enable export")
	}
	if e := validateSettings(s); e != nil {
		return "", e
	}
	if s.Endpoint == "" {
		return "", errors.New("save a public endpoint before exporting configurations")
	}
	psk := ""
	if p.PSK != "" {
		psk = "PresharedKey = " + p.PSK + "\n"
	}
	dns := ""
	if s.DNS != "" {
		dns = "DNS = " + s.DNS + "\n"
	}
	routes, err := clientRoutes(s, p.Peer)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n%s\n[Peer]\nPublicKey = %s\n%sEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", p.Private, p.Address, dns, serverPublic, psk, s.Endpoint, routes, s.PersistentKeepalive), nil
}
