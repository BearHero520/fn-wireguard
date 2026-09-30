package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
)

func managedAccess(s Settings) bool { return s.AccessMode == "lan" || s.AccessMode == "selected" }

func validateTargets(mode, subnet string, targets []string, peer bool) error {
	if peer && (mode == "" || mode == "inherit") {
		if len(targets) > 0 {
			return errors.New("inherited access cannot contain device targets")
		}
		return nil
	}
	if mode != "lan" && mode != "selected" {
		return errors.New("invalid access mode")
	}
	if mode == "lan" {
		if len(targets) > 0 {
			return errors.New("whole LAN access cannot contain device targets")
		}
		return nil
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() < 16 || prefix.Bits() > 30 {
		return errors.New("LAN network is not detected")
	}
	if len(targets) == 0 || len(targets) > 128 {
		return errors.New("select 1–128 LAN devices")
	}
	seen := map[string]bool{}
	for _, target := range targets {
		ip, err := netip.ParseAddr(target)
		if err != nil || !ip.Is4() || !prefix.Contains(ip) || ip == prefix.Masked().Addr() || ip == lastAddress(prefix) || seen[target] {
			return fmt.Errorf("invalid or duplicate LAN device: %s", target)
		}
		seen[target] = true
	}
	return nil
}

func accessTargets(s Settings, p Peer) ([]string, error) {
	mode, targets := s.AccessMode, s.AllowedDevices
	if p.AccessMode != "" && p.AccessMode != "inherit" {
		mode, targets = p.AccessMode, p.AllowedDevices
	}
	if !managedAccess(s) {
		if p.AccessMode != "" && p.AccessMode != "inherit" {
			return nil, errors.New("enable LAN access before setting client permissions")
		}
		return nil, nil
	}
	prefix, err := netip.ParsePrefix(s.LANSubnet)
	local, le := netip.ParseAddr(s.LANAddress)
	if err != nil || le != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() < 16 || prefix.Bits() > 30 || !prefix.Contains(local) || local == prefix.Masked().Addr() || local == lastAddress(prefix) {
		return nil, errors.New("LAN network is not detected")
	}
	if err = validateTargets(mode, s.LANSubnet, targets, false); err != nil {
		return nil, err
	}
	if mode == "lan" {
		return []string{prefix.Masked().String()}, nil
	}
	result := append([]string(nil), targets...)
	sort.Strings(result)
	for i := range result {
		result[i] += "/32"
	}
	return result, nil
}

func clientRoutes(s Settings, p Peer) (string, error) {
	if !managedAccess(s) {
		return s.AllowedIPs, nil
	}
	targets, err := accessTargets(s, p)
	if err != nil {
		return "", err
	}
	server, err := serverPrefix(s.Address)
	if err != nil {
		return "", err
	}
	// The NAS tunnel address is allowed only when the NAS itself is allowed.
	nasAllowed := false
	for _, target := range targets {
		prefix, _ := netip.ParsePrefix(target)
		if prefix.Contains(netip.MustParseAddr(s.LANAddress)) {
			nasAllowed = true
		}
	}
	if nasAllowed {
		targets = append([]string{server.Addr().String() + "/32"}, targets...)
	}
	return strings.Join(targets, ", "), nil
}

func accessChanged(a, b Settings) bool {
	if a.AccessMode == "" {
		a.AccessMode = "custom"
	}
	if b.AccessMode == "" {
		b.AccessMode = "custom"
	}
	return a.AccessMode != b.AccessMode || a.LANSubnet != b.LANSubnet || a.LANAddress != b.LANAddress || a.LANInterface != b.LANInterface || !reflect.DeepEqual(a.AllowedDevices, b.AllowedDevices)
}

func (a *App) prepareAccess(s Settings) (Settings, error) {
	if s.AccessMode == "" {
		s.AccessMode = "custom"
	}
	if s.AccessMode == "custom" {
		s.LANSubnet = ""
		s.LANAddress = ""
		s.LANInterface = ""
		s.AllowedDevices = nil
		return s, nil
	}
	if !managedAccess(s) {
		return s, errors.New("invalid access mode")
	}
	info, err := a.lan.Info()
	if err != nil {
		return s, err
	}
	s.LANSubnet, s.LANAddress, s.LANInterface = info.Subnet, info.Address, info.Interface
	routes, err := clientRoutes(s, Peer{})
	if err != nil {
		return s, err
	}
	s.AllowedIPs = routes
	return s, nil
}

func (a *App) initializeAccess() error {
	s, _, _, err := a.store.settings()
	if err != nil {
		return err
	}
	if s.AccessMode != "" {
		return nil
	}
	subnet, _ := serverPrefix(s.Address)
	// Preserve deliberately customized legacy routes. Upgrade the former tunnel-
	// only default to the requested LAN default, without changing keys or peers.
	if s.AllowedIPs == subnet.Masked().String() {
		s.AccessMode = "lan"
		if prepared, e := a.prepareAccess(s); e == nil {
			s = prepared
		}
	} else {
		s.AccessMode = "custom"
	}
	encoded, _ := json.Marshal(s)
	_, err = a.store.db.Exec("UPDATE settings SET value=? WHERE id=1", string(encoded))
	return err
}
