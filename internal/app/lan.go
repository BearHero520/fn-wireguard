package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type LANDevice struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac,omitempty"`
	Name   string `json:"name"`
	Status string `json:"status"`
}
type LANInfo struct {
	Available  bool        `json:"available"`
	Reason     string      `json:"reason,omitempty"`
	Subnet     string      `json:"subnet"`
	Address    string      `json:"address"`
	Interface  string      `json:"interface"`
	Gateway    string      `json:"gateway"`
	ScanSubnet string      `json:"scanSubnet,omitempty"`
	Devices    []LANDevice `json:"devices"`
}
type LANProvider interface {
	Info() (LANInfo, error)
	Discover(context.Context) (LANInfo, error)
}
type systemLAN struct{ mode string }

func ipRead(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "ip", args...).Output()
}
func (l systemLAN) Info() (LANInfo, error) {
	if runtime.GOOS != "linux" || l.mode != "production" {
		return LANInfo{}, errors.New("LAN discovery requires the NAS runtime")
	}
	routes, err := ipRead("-json", "-4", "route", "show", "default")
	if err != nil {
		return LANInfo{}, errors.New("cannot detect the LAN gateway")
	}
	addresses, err := ipRead("-json", "-4", "address", "show")
	if err != nil {
		return LANInfo{}, errors.New("cannot detect the LAN network")
	}
	info, err := detectLAN(routes, addresses)
	if err != nil {
		return info, err
	}
	raw, err := ipRead("-json", "neigh", "show", "dev", info.Interface)
	if err == nil {
		info.Devices = parseNeighbours(info, raw, nil)
	} else {
		info.Devices = parseNeighbours(info, nil, nil)
	}
	return info, nil
}

func detectLAN(routeData, addressData []byte) (LANInfo, error) {
	var routes []struct {
		Dev, Gateway string
		Metric       int
	}
	var addresses []struct {
		IfName   string
		AddrInfo []struct {
			Family, Local, Scope string
			PrefixLen            int
		} `json:"addr_info"`
	}
	if json.Unmarshal(routeData, &routes) != nil || json.Unmarshal(addressData, &addresses) != nil {
		return LANInfo{}, errors.New("cannot parse LAN network information")
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].Metric < routes[j].Metric })
	for _, route := range routes {
		if route.Dev == iface || strings.HasPrefix(route.Dev, "docker") || strings.HasPrefix(route.Dev, "br-") || strings.HasPrefix(route.Dev, "veth") || route.Dev == "lo" {
			continue
		}
		for _, device := range addresses {
			if device.IfName != route.Dev {
				continue
			}
			for _, address := range device.AddrInfo {
				ip, err := netip.ParseAddr(address.Local)
				if err != nil || !ip.Is4() || !ip.IsPrivate() || address.PrefixLen < 16 || address.PrefixLen > 30 {
					continue
				}
				prefix := netip.PrefixFrom(ip, address.PrefixLen).Masked()
				gateway, err := netip.ParseAddr(route.Gateway)
				if err != nil || !prefix.Contains(gateway) {
					continue
				}
				return LANInfo{Available: true, Subnet: prefix.String(), Address: ip.String(), Interface: route.Dev, Gateway: gateway.String(), Devices: []LANDevice{}}, nil
			}
		}
	}
	return LANInfo{}, errors.New("no private IPv4 LAN found on the default gateway interface")
}

func parseNeighbours(info LANInfo, raw []byte, seen map[string]bool) []LANDevice {
	prefix, err := netip.ParsePrefix(info.Subnet)
	if err != nil {
		return []LANDevice{}
	}
	devices := map[string]LANDevice{info.Address: {IP: info.Address, Name: "飞牛 NAS", Status: "local"}}
	var rows []struct {
		Dst, LLAddr string
		State       []string
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &rows)
	}
	for _, row := range rows {
		ip, err := netip.ParseAddr(row.Dst)
		if err != nil || !prefix.Contains(ip) || row.LLAddr == "" || row.Dst == info.Address {
			continue
		}
		failed := false
		for _, state := range row.State {
			if state == "FAILED" || state == "INCOMPLETE" {
				failed = true
			}
		}
		if failed {
			continue
		}
		status := "cached"
		if seen[row.Dst] {
			status = "responded"
		}
		name := "局域网设备"
		if row.Dst == info.Gateway {
			name = "路由器 / 网关"
		}
		devices[row.Dst] = LANDevice{IP: row.Dst, MAC: row.LLAddr, Name: name, Status: status}
	}
	for ip, yes := range seen {
		if !yes || ip == info.Address {
			continue
		}
		if _, ok := devices[ip]; !ok {
			devices[ip] = LANDevice{IP: ip, Name: "局域网设备", Status: "responded"}
		}
	}
	result := make([]LANDevice, 0, len(devices))
	for _, d := range devices {
		result = append(result, d)
	}
	sort.Slice(result, func(i, j int) bool { return netip.MustParseAddr(result[i].IP).Less(netip.MustParseAddr(result[j].IP)) })
	return result
}

func (l systemLAN) Discover(ctx context.Context) (LANInfo, error) {
	info, err := l.Info()
	if err != nil {
		return info, err
	}
	prefix, _ := netip.ParsePrefix(info.Subnet)
	if prefix.Bits() < 24 {
		prefix = netip.PrefixFrom(netip.MustParseAddr(info.Address), 24).Masked()
	}
	info.ScanSubnet = prefix.String()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	jobs := make(chan netip.Addr)
	seen := map[string]bool{}
	var mu sync.Mutex
	var workers sync.WaitGroup
	for i := 0; i < 24; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ip := range jobs {
				// A single TCP connection attempt triggers normal ARP discovery. No raw
				// sockets, application payloads, credential attempts or arbitrary subnets.
				dialer := net.Dialer{Timeout: 350 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP(info.Address)}}
				conn, e := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), "80"))
				if e == nil {
					conn.Close()
					mu.Lock()
					seen[ip.String()] = true
					mu.Unlock()
				}
			}
		}()
	}
loop:
	for ip := prefix.Addr().Next(); ip != lastAddress(prefix); ip = ip.Next() {
		if ip.String() == info.Address {
			continue
		}
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break loop
		}
	}
	close(jobs)
	workers.Wait()
	raw, err := ipRead("-json", "neigh", "show", "dev", info.Interface)
	if err != nil {
		return info, errors.New("cannot read discovered LAN devices")
	}
	info.Devices = parseNeighbours(info, raw, seen)
	return info, nil
}

func (a *App) lanRoute(w http.ResponseWriter, r *http.Request) {
	var info LANInfo
	var err error
	if r.Method == "POST" {
		if time.Since(a.lastLANScan) < 10*time.Second {
			fail(w, 429, "LAN scan is cooling down; retry after 10 seconds")
			return
		}
		a.lastLANScan = time.Now()
		info, err = a.lan.Discover(r.Context())
	} else {
		info, err = a.lan.Info()
	}
	if err != nil {
		respond(w, 200, LANInfo{Reason: err.Error(), Devices: []LANDevice{}})
		return
	}
	respond(w, 200, info)
}
