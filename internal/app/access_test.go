package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type fixtureLAN struct{ scans int }

func (f *fixtureLAN) Info() (LANInfo, error) {
	return LANInfo{Available: true, Subnet: "192.168.50.0/24", Address: "192.168.50.200", Interface: "enp5s0-ovs", Gateway: "192.168.50.2", Devices: []LANDevice{}}, nil
}
func (f *fixtureLAN) Discover(context.Context) (LANInfo, error) { f.scans++; return f.Info() }
func lanSettings() Settings {
	s := defaultSettings()
	s.AccessMode = "lan"
	s.LANSubnet = "192.168.50.0/24"
	s.LANAddress = "192.168.50.200"
	s.LANInterface = "enp5s0-ovs"
	return s
}

func TestAccessRoutesAndRejection(t *testing.T) {
	s := lanSettings()
	for _, tc := range []struct {
		mode    string
		targets []string
		want    string
	}{
		{"inherit", nil, "10.66.66.1/32, 192.168.50.0/24"},
		{"selected", []string{"192.168.50.10"}, "192.168.50.10/32"},
		{"selected", []string{"192.168.50.200"}, "10.66.66.1/32, 192.168.50.200/32"},
	} {
		got, e := clientRoutes(s, Peer{AccessMode: tc.mode, AllowedDevices: tc.targets})
		if e != nil || got != tc.want {
			t.Fatal(tc, got, e)
		}
	}
	s.AccessMode = "selected"
	s.AllowedDevices = []string{"192.168.50.10"}
	got, e := clientRoutes(s, Peer{AccessMode: "lan"})
	if e != nil || !strings.Contains(got, "192.168.50.0/24") {
		t.Fatal(got, e)
	}
	for _, targets := range [][]string{nil, {"8.8.8.8"}, {"192.168.50.0"}, {"192.168.50.255"}, {"192.168.50.10", "192.168.50.10"}, {"192.168.50.10; accept"}, {"192.168.50.10/32"}, {"::1"}} {
		if _, e := clientRoutes(s, Peer{AccessMode: "selected", AllowedDevices: targets}); e == nil {
			t.Fatal("unsafe target accepted", targets)
		}
	}
	s.AccessMode = "custom"
	s.AllowedIPs = "10.66.66.0/24"
	if _, e := accessTargets(s, Peer{AccessMode: "selected", AllowedDevices: []string{"192.168.50.10"}}); e == nil {
		t.Fatal("custom mode accepted peer ACL")
	}
}

func TestLANDetectionAndNeighbourScope(t *testing.T) {
	routes := []byte(`[{"dev":"docker0","gateway":"172.17.0.1","metric":0},{"dev":"enp5s0-ovs","gateway":"192.168.50.2","metric":100}]`)
	addresses := []byte(`[{"ifname":"docker0","addr_info":[{"local":"172.17.0.2","prefixlen":16}]},{"ifname":"enp5s0-ovs","addr_info":[{"local":"192.168.50.200","prefixlen":24}]}]`)
	info, e := detectLAN(routes, addresses)
	if e != nil || info.Subnet != "192.168.50.0/24" || info.Interface != "enp5s0-ovs" {
		t.Fatal(info, e)
	}
	devices := parseNeighbours(info, []byte(`[{"dst":"192.168.50.2","lladdr":"00:11:22:33:44:55","state":["STALE"]},{"dst":"192.168.50.3","lladdr":"00:11:22:33:44:66","state":["FAILED"]},{"dst":"172.17.0.3","lladdr":"00:11:22:33:44:77","state":["REACHABLE"]}]`), nil)
	if len(devices) != 2 || devices[0].IP != "192.168.50.2" || devices[0].Status != "cached" || devices[1].Status != "local" {
		t.Fatal(devices)
	}
	for _, bad := range []string{`[]`, `[{"dev":"docker0","gateway":"172.17.0.1"}]`, `[{"dev":"enp5s0-ovs","gateway":"8.8.8.8"}]`} {
		if _, e = detectLAN([]byte(bad), addresses); e == nil {
			t.Fatal("unsafe detection", bad)
		}
	}
}

func TestAccessPersistenceAndLiveRollback(t *testing.T) {
	lan := &fixtureLAN{}
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos", LANProvider: lan})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	s, priv, _, e := a.store.settings()
	if e != nil || s.AccessMode != "lan" || s.AllowedIPs != "10.66.66.1/32, 192.168.50.0/24" {
		t.Fatal(s, e)
	}
	s.Endpoint = "nas.example:5999"
	body, _ := json.Marshal(s)
	w := httptest.NewRecorder()
	a.saveSettings(w, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(string(body))))
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	w = httptest.NewRecorder()
	a.createPeer(w, httptest.NewRequest("POST", "/api/peers", strings.NewReader(`{"name":"Phone","deviceType":"phone"}`)))
	if w.Code != 201 {
		t.Fatal(w.Body)
	}
	var peer Peer
	if e = json.Unmarshal(w.Body.Bytes(), &peer); e != nil {
		t.Fatal(e)
	}
	patch := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.peerRoute(w, httptest.NewRequest("PATCH", "/api/peers/"+peer.ID, strings.NewReader(body)))
		return w
	}
	if w = patch(`{"accessMode":"selected","allowedDevices":["192.168.50.10"]}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	ps, e := a.store.peers()
	if e != nil || len(ps) != 1 || ps[0].AccessMode != "selected" || len(ps[0].AllowedDevices) != 1 {
		t.Fatal(ps, e)
	}
	config, e := clientConfig(s, ps[0], "public-fixture")
	if e != nil || !strings.Contains(config, "AllowedIPs = 192.168.50.10/32\n") || strings.Contains(config, "DNS =") {
		t.Fatal("incorrect export", e)
	}
	f := &failingAdapter{running: true, fail: true}
	a.adapter = f
	a.options.Mode = "production"
	if w = patch(`{"accessMode":"lan","allowedDevices":[]}`); w.Code != 503 {
		t.Fatal(w.Code, w.Body)
	}
	if f.applies != 2 {
		t.Fatal("runtime rollback not attempted")
	}
	ps, _ = a.store.peers()
	if ps[0].AccessMode != "selected" {
		t.Fatal("failed runtime change persisted")
	}
	if a.runtimeError != "" {
		t.Fatal("successful rollback left runtime locked", a.runtimeError)
	}
	if w = patch(`{"accessMode":"lan","allowedDevices":[]}`); w.Code != 200 || f.applies != 3 {
		t.Fatal("retry after rollback failed", w.Code, w.Body, f.applies)
	}
	f.running = false
	for _, bad := range []string{`{"accessMode":"selected","allowedDevices":[]}`, `{"accessMode":"lan","allowedDevices":["192.168.50.10"]}`, `{"accessMode":"inherit","allowedDevices":["192.168.50.10"]}`, `{"enabled":true,"allowedDevices":["192.168.50.10"]}`} {
		if w = patch(bad); w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if w = patch(`{"accessMode":"inherit","allowedDevices":[]}`); w.Code != 200 {
		t.Fatal(w.Body)
	}
	ps, _ = a.store.peers()
	if ps[0].AccessMode != "inherit" {
		t.Fatal("inherit not stored")
	}
	// Global changes cannot silently discard an explicit client policy.
	if w = patch(`{"accessMode":"selected","allowedDevices":["192.168.50.10"]}`); w.Code != 200 {
		t.Fatal(w.Body)
	}
	custom := s
	custom.AccessMode = "custom"
	body, _ = json.Marshal(custom)
	w = httptest.NewRecorder()
	a.saveSettings(w, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(string(body))))
	if w.Code != 400 {
		t.Fatal("override silently discarded", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	a.peerRoute(w, httptest.NewRequest("DELETE", "/api/peers/"+peer.ID, nil))
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	var count int
	a.store.db.QueryRow("SELECT COUNT(*) FROM peer_access").Scan(&count)
	if count != 0 {
		t.Fatal("orphan ACL")
	}
	_, nextPriv, _, _ := a.store.settings()
	if nextPriv != priv {
		t.Fatal("server key changed")
	}
}

func TestLANRouteAuthenticationAndScanCooldown(t *testing.T) {
	lan := &fixtureLAN{}
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "local", LANProvider: lan})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if w := request(a, "POST", "/api/lan/scan", "{}", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	cw := httptest.NewRecorder()
	session, e := a.newSession(cw, "admin", "")
	if e != nil {
		t.Fatal(e)
	}
	cookie := cw.Result().Cookies()[0]
	if w := request(a, "POST", "/api/lan/scan", "{}", "", cookie); w.Code != 403 {
		t.Fatal("scan without CSRF", w.Code)
	}
	if w := request(a, "POST", "/api/lan/scan", "{}", session.CSRF, cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := request(a, "POST", "/api/lan/scan", "{}", session.CSRF, cookie); w.Code != 429 || lan.scans != 1 {
		t.Fatal("scan cooldown", w.Code, lan.scans)
	}
}

func TestFirewallPlanOwnershipAndRestriction(t *testing.T) {
	snapshot := []byte(`{"nftables":[{"table":{"family":"ip","name":"filter"}},{"chain":{"family":"ip","table":"filter","name":"FORWARD","type":"filter","hook":"forward","policy":"drop"}},{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":9,"comment":"docker-rule"}}]}`)
	peers := []runtimePeer{{Peer: Peer{Address: "10.66.66.2/32", Enabled: true}}, {Peer: Peer{Address: "10.66.66.3/32", Enabled: true, AccessMode: "selected", AllowedDevices: []string{"192.168.50.10"}}}, {Peer: Peer{Address: "10.66.66.4/32", Enabled: false}}}
	plan, e := firewallPlan(snapshot, lanSettings(), peers, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, expected := range []string{`ip saddr 10.66.66.3/32 oifname "enp5s0-ovs" ip daddr { 192.168.50.10/32 }`, `insert rule ip filter FORWARD`, `ct original ip daddr { 192.168.50.200, 10.66.66.1 }`, `counter masquerade`, `iifname "fnwg0" counter drop`, `oifname "fnwg0" counter drop`} {
		if !strings.Contains(plan, expected) {
			t.Fatal("missing scoped rule", expected)
		}
	}
	for _, forbidden := range []string{"flush", "policy drop", "delete rule", "10.66.66.4/32", "0.0.0.0/0"} {
		if strings.Contains(plan, forbidden) {
			t.Fatal("unexpected change", forbidden)
		}
	}
	for _, line := range strings.Split(plan, "\n") {
		if strings.Contains(line, "10.66.66.3/32") && (strings.Contains(line, "ct status dnat") || strings.Contains(line, " input ")) {
			t.Fatal("restricted client can reach NAS", line)
		}
	}
	if path := os.Getenv("FNWG_NFT_PLAN_OUT"); path != "" {
		if e = os.WriteFile(path, []byte(plan), 0600); e != nil {
			t.Fatal(e)
		}
	}
	owned := []byte(`{"nftables":[{"table":{"family":"inet","name":"fnwg_access","handle":10,"comment":"fn-wireguard-managed-v1"}},{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":12,"comment":"fn-wireguard-managed-v1"}},{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":13,"comment":"another-app"}}]}`)
	cleanup, e := firewallPlan(owned, Settings{}, nil, nil)
	if e != nil || cleanup != "delete table inet handle 10\ndelete rule ip filter FORWARD handle 12\n" {
		t.Fatal(cleanup, e)
	}
	if _, e = firewallPlan([]byte(`{"nftables":[{"table":{"family":"inet","name":"fnwg_access","comment":"foreign"}}]}`), lanSettings(), nil, nil); e == nil {
		t.Fatal("foreign table overwritten")
	}
	bad := lanSettings()
	bad.LANInterface = "eth0; flush ruleset"
	if _, e = firewallPlan(snapshot, bad, peers, nil); e == nil {
		t.Fatal("interface injection")
	}
	bad = lanSettings()
	bad.LANSubnet = "10.66.66.0/24"
	bad.LANAddress = "10.66.66.200"
	if _, e = firewallPlan(snapshot, bad, peers, nil); e == nil {
		t.Fatal("overlap accepted")
	}
}

type unavailableLAN struct{}

func (unavailableLAN) Info() (LANInfo, error) { return LANInfo{}, errors.New("no LAN") }
func (unavailableLAN) Discover(context.Context) (LANInfo, error) {
	return LANInfo{}, errors.New("no LAN")
}
func TestAccessMigrationPreservesCustomRoutes(t *testing.T) {
	a, e := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	a.lan = unavailableLAN{}
	s, priv, _, _ := a.store.settings()
	s.AllowedIPs = "10.66.66.0/24, 192.168.7.0/24"
	data, _ := json.Marshal(s)
	a.store.db.Exec("UPDATE settings SET value=?", string(data))
	if e = a.initializeAccess(); e != nil {
		t.Fatal(e)
	}
	next, nextPriv, _, _ := a.store.settings()
	if next.AccessMode != "custom" || next.AllowedIPs != s.AllowedIPs || nextPriv != priv {
		t.Fatal("legacy configuration changed")
	}
}
