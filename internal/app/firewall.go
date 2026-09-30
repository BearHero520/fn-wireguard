package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const accessTable = "fnwg_access"

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

var accessTableHeader = regexp.MustCompile(`^table inet fnwg_access \{ # handle ([1-9][0-9]*)$`)

// nftables 1.0.6 omits table comments from JSON. Its text listing prints the
// table comment immediately after the header, before any chains or rules.
// Match that position and the snapshot's handle, never a nested rule comment.
func ownsFirewallTableText(raw []byte, handle uint64) bool {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if handle == 0 || len(lines) < 3 {
		return false
	}
	header := accessTableHeader.FindStringSubmatch(strings.TrimSpace(lines[0]))
	if header == nil || header[1] != strconv.FormatUint(handle, 10) {
		return false
	}
	return strings.TrimSpace(lines[1]) == "comment "+strconv.Quote(ownership) && strings.TrimSpace(lines[len(lines)-1]) == "}"
}

// A single nft transaction replaces our rules. Never flush a host table or
// change Docker's policy. An earlier base chain enforces revocations even for
// established connections; narrowly scoped FORWARD rules cross Docker's DROP.
func firewallPlan(raw []byte, s Settings, peers []runtimePeer, readTable func() ([]byte, error)) (string, error) {
	var snapshot struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return "", errors.New("cannot read nftables rules")
	}
	var out strings.Builder
	compat := false
	for _, entry := range snapshot.NFTables {
		if value, ok := entry["table"]; ok {
			var t struct {
				Family, Name string
				Comment      *string
				Handle       uint64
			}
			if err := json.Unmarshal(value, &t); err != nil {
				return "", err
			}
			if t.Family == "inet" && t.Name == accessTable {
				owned := t.Comment != nil && *t.Comment == ownership
				if t.Comment == nil && readTable != nil {
					text, err := readTable()
					if err != nil {
						return "", fmt.Errorf("cannot verify LAN firewall table ownership: %w", err)
					}
					owned = ownsFirewallTableText(text, t.Handle)
				}
				if !owned {
					return "", errors.New("LAN firewall table is not owned by this application")
				}
				if t.Handle == 0 {
					return "", errors.New("cannot read LAN firewall table handle")
				}
				// A concurrent same-name replacement must not be deleted.
				fmt.Fprintf(&out, "delete table inet handle %d\n", t.Handle)
			}
		}
		if value, ok := entry["chain"]; ok {
			var c struct{ Family, Table, Name, Hook, Type string }
			if err := json.Unmarshal(value, &c); err != nil {
				return "", err
			}
			if c.Family == "ip" && c.Table == "filter" && c.Name == "FORWARD" && c.Hook == "forward" && c.Type == "filter" {
				compat = true
			}
		}
		if value, ok := entry["rule"]; ok {
			var r struct {
				Family, Table, Chain, Comment string
				Handle                        uint64
			}
			if err := json.Unmarshal(value, &r); err != nil {
				return "", err
			}
			if r.Family == "ip" && r.Table == "filter" && r.Chain == "FORWARD" && r.Comment == ownership && r.Handle > 0 {
				fmt.Fprintf(&out, "delete rule ip filter FORWARD handle %d\n", r.Handle)
			}
		}
	}
	if !managedAccess(s) {
		return out.String(), nil
	}
	if !interfaceName.MatchString(s.LANInterface) || s.LANInterface == iface || s.LANInterface == "lo" {
		return "", errors.New("invalid LAN interface")
	}
	if _, err := accessTargets(s, Peer{}); err != nil {
		return "", err
	}
	tunnel, err := serverPrefix(s.Address)
	if err != nil {
		return "", err
	}
	lanPrefix, _ := netip.ParsePrefix(s.LANSubnet)
	if tunnel.Overlaps(lanPrefix) {
		return "", errors.New("tunnel subnet overlaps LAN network")
	}
	// Unlike add, create rejects a same-name table that appeared after reading.
	fmt.Fprintf(&out, "create table inet %s { comment %q; }\n", accessTable, ownership)
	fmt.Fprintf(&out, "add chain inet %s input { type filter hook input priority -10; policy accept; }\n", accessTable)
	fmt.Fprintf(&out, "add chain inet %s forward { type filter hook forward priority -10; policy accept; }\n", accessTable)
	fmt.Fprintf(&out, "add chain inet %s postrouting { type nat hook postrouting priority 100; policy accept; }\n", accessTable)
	add := func(chain, match, verdict string) {
		fmt.Fprintf(&out, "add rule inet %s %s %s counter %s\n", accessTable, chain, match, verdict)
	}
	forward := func(match string) { add("forward", match, "accept") }
	// Keep the iptables-nft FORWARD chain representable by iptables: complex
	// sets and original-DNAT matching belong exclusively to our earlier inet
	// chain. These simple compatibility gates and that chain change atomically.
	if compat {
		fmt.Fprintf(&out, "insert rule ip filter FORWARD iifname %q ip saddr %s counter accept comment %q\n", iface, tunnel.Masked(), ownership)
		fmt.Fprintf(&out, "insert rule ip filter FORWARD oifname %q ip daddr %s ct state established,related counter accept comment %q\n", iface, tunnel.Masked(), ownership)
	}

	seen := map[string]bool{}
	for _, p := range peers {
		if !p.Enabled {
			continue
		}
		address, e := netip.ParsePrefix(p.Address)
		if e != nil || !address.Addr().Is4() || address.Bits() != 32 || !tunnel.Contains(address.Addr()) || address.Addr() == tunnel.Addr() || address.Addr() == tunnel.Masked().Addr() || address.Addr() == lastAddress(tunnel) || seen[p.Address] {
			return "", errors.New("invalid firewall peer address")
		}
		seen[p.Address] = true
		targets, e := accessTargets(s, p.Peer)
		if e != nil {
			return "", e
		}
		targetSet := "{ " + strings.Join(targets, ", ") + " }"
		source := fmt.Sprintf("iifname %q ip saddr %s", iface, p.Address)
		destination := fmt.Sprintf("oifname %q ip daddr %s", iface, p.Address)
		nasAllowed := false
		for _, v := range targets {
			prefix, _ := netip.ParsePrefix(v)
			if prefix.Contains(netip.MustParseAddr(s.LANAddress)) {
				nasAllowed = true
			}
		}
		// Input is restricted to the NAS's primary LAN and tunnel addresses.
		if nasAllowed {
			add("input", source+" ip daddr { "+s.LANAddress+", "+tunnel.Addr().String()+" }", "accept")
		}
		outbound := source + " oifname " + strconv.Quote(s.LANInterface) + " ip daddr " + targetSet
		forward(outbound)
		forward(destination + " iifname " + strconv.Quote(s.LANInterface) + " ip saddr " + targetSet + " ct state established,related")
		add("postrouting", outbound, "masquerade")
		if nasAllowed {
			// Docker-published NAS ports have already been DNATed at this point.
			original := " ct status dnat ct original ip daddr { " + s.LANAddress + ", " + tunnel.Addr().String() + " }"
			forward(source + " oifname != " + strconv.Quote(iface) + original)
			forward(destination + " ct state established,related" + original)
			add("postrouting", source+" oifname != "+strconv.Quote(iface)+original, "masquerade")
		}
	}
	add("input", fmt.Sprintf("iifname %q", iface), "drop")
	add("forward", fmt.Sprintf("iifname %q", iface), "drop")
	add("forward", fmt.Sprintf("oifname %q", iface), "drop")
	return out.String(), nil
}

func nftCommand(input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", args...)
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("LAN firewall operation failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}

func applyFirewall(s Settings, peers []runtimePeer) (err error) {
	// Only read-only checks are safe to retry without rolling back. Once the
	// transaction has been sent, even a timeout needs runtime reconciliation.
	checking := true
	defer func() {
		if err != nil && checking {
			err = &runtimeUnchangedError{err}
		}
		if err != nil {
			log.Printf("LAN firewall: %v", err)
		}
	}()
	if _, err := exec.LookPath("nft"); err != nil {
		if !managedAccess(s) {
			return nil
		}
		return errors.New("nft is required for LAN access")
	}
	if managedAccess(s) {
		data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil || strings.TrimSpace(string(data)) != "1" {
			return errors.New("IPv4 forwarding is disabled; restart the NAS application to prepare LAN access")
		}
		info, err := (systemLAN{mode: "production"}).Info()
		if err != nil {
			return err
		}
		if info.Subnet != s.LANSubnet || info.Address != s.LANAddress || info.Interface != s.LANInterface {
			return errors.New("LAN network changed; stop the server and save connection settings again")
		}
	}
	checking = false
	return applyFirewallRules(s, peers, nftCommand)
}

func applyFirewallRules(s Settings, peers []runtimePeer, run func(string, ...string) ([]byte, error)) error {
	raw, err := run("", "-j", "list", "ruleset")
	if err != nil {
		return &runtimeUnchangedError{err}
	}
	plan, err := firewallPlan(raw, s, peers, func() ([]byte, error) {
		return run("", "-s", "-a", "list", "table", "inet", accessTable)
	})
	if err != nil {
		return &runtimeUnchangedError{err}
	}
	if plan == "" {
		return nil
	}
	_, err = run(plan, "-f", "-")
	return err
}
