package app

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestUDPPortProbe(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "udp6" {
				address = "[::1]:0"
			}
			conn, err := net.ListenPacket(network, address)
			if err != nil {
				if network == "udp6" && ipv6Unavailable(err) {
					t.Skip("IPv6 unavailable")
				}
				t.Fatal(err)
			}
			defer conn.Close()
			port := conn.LocalAddr().(*net.UDPAddr).Port
			if state, detail := probeUDP(port); state != "in-use" {
				t.Fatalf("occupied %s: %s %s", network, state, detail)
			}
			conn.Close()
			if state, detail := probeUDP(port); state != "available" {
				t.Fatalf("released %s: %s %s", network, state, detail)
			}
			// The diagnostic must not keep the port bound after returning.
			again, err := net.ListenPacket(network, net.JoinHostPort("", strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			again.Close()
		})
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if state, detail := probeUDP(listener.Addr().(*net.TCPAddr).Port); state != "available" {
		t.Fatal("TCP listener incorrectly blocked UDP", state, detail)
	}
}

func TestOnlyUpOwnedInterfaceCountsAsRunning(t *testing.T) {
	for _, tc := range []struct {
		data             string
		exists, up, fail bool
	}{
		{`[]`, false, false, false},
		{`[{"ifname":"fnwg0","ifalias":"fn-wireguard-managed-v1","flags":["NOARP"]}]`, true, false, false},
		{`[{"ifname":"fnwg0","ifalias":"fn-wireguard-managed-v1","flags":["NOARP","UP"]}]`, true, true, false},
		{`[{"ifname":"fnwg0","ifalias":"other","flags":["UP"]}]`, false, false, true},
		{`invalid`, false, false, true},
	} {
		exists, up, err := ownedLinkState([]byte(tc.data))
		if exists != tc.exists || up != tc.up || (err != nil) != tc.fail {
			t.Fatal(tc.data, exists, up, err)
		}
	}
}

func TestPortInspectionUsesActualRuntime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status RuntimeStatus
		port   int
		want   string
		calls  int
	}{
		{"own active port", RuntimeStatus{Running: true, Available: true, ListenPort: 12345}, 12345, "active", 0},
		{"saved differs from running", RuntimeStatus{Running: true, Available: true, ListenPort: 51820}, 12345, "available", 1},
		{"stopped", RuntimeStatus{Available: true}, 12345, "available", 1},
		{"unavailable", RuntimeStatus{Reason: "runtime unavailable"}, 12345, "unknown", 0},
		{"uncertain", RuntimeStatus{Available: true, Reason: "state unresolved"}, 12345, "unknown", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			result := inspectPort(tc.port, tc.status, func(int) (string, string) { calls++; return "available", "" })
			if result.State != tc.want || calls != tc.calls || result.ActualPort != tc.status.ListenPort || result.CheckedAt == "" {
				t.Fatal(result, calls)
			}
		})
	}
	result := inspectPort(12345, RuntimeStatus{Available: true}, func(int) (string, string) { return "unknown", "permission denied" })
	if result.State != "unknown" || result.Detail != "permission denied" {
		t.Fatal(result)
	}
}

type portRecordingAdapter struct {
	failingAdapter
	port int
}

func (f *portRecordingAdapter) Status() RuntimeStatus {
	s := f.failingAdapter.Status()
	if s.Running {
		s.ListenPort = f.port
	}
	return s
}
func (f *portRecordingAdapter) Start(s Settings, _ string, _ []runtimePeer) error {
	f.port = s.ListenPort
	f.running = true
	return nil
}

func TestSavedPortsReachRuntimeAndExports(t *testing.T) {
	a, err := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	adapter := &portRecordingAdapter{}
	a.adapter = adapter
	for _, endpoint := range []string{"vpn.example.com:23456", "vpn.example.com:443", "[2001:db8::1]:23456"} {
		adapter.running = false
		s := defaultSettings()
		s.Endpoint = endpoint
		s.ListenPort = 23456
		body, _ := json.Marshal(s)
		w := httptest.NewRecorder()
		a.saveSettings(w, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(string(body))))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		stored, private, public, err := a.store.settings()
		if err != nil {
			t.Fatal(err)
		}
		client, err := clientConfig(stored, runtimePeer{Peer: Peer{Address: "10.66.66.2/32"}, Private: private}, public)
		if err != nil || !strings.Contains(client, "Endpoint = "+endpoint+"\n") {
			t.Fatal("client export kept old port", err)
		}
		w = httptest.NewRecorder()
		a.server(w, httptest.NewRequest("POST", "/api/server/start", nil))
		if w.Code != 200 || adapter.port != 23456 {
			t.Fatal("new port did not reach runtime", w.Code, adapter.port)
		}
		var view struct {
			Server struct {
				ListenPort       int `json:"listenPort"`
				ActualListenPort int `json:"actualListenPort"`
			}
		}
		if err = json.Unmarshal(w.Body.Bytes(), &view); err != nil || view.Server.ListenPort != 23456 || view.Server.ActualListenPort != 23456 {
			t.Fatal(view, err)
		}
		w = httptest.NewRecorder()
		a.checkPort(w, httptest.NewRequest("POST", "/api/server/port-check", strings.NewReader(`{"port":23456}`)))
		var result portCheck
		if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.State != "active" {
			t.Fatal(result, err)
		}
	}
	for _, body := range []string{`{"port":0}`, `{"port":65536}`, `{"port":1.5}`, `{}`} {
		w := httptest.NewRecorder()
		a.checkPort(w, httptest.NewRequest("POST", "/api/server/port-check", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("invalid port accepted", body, w.Code)
		}
	}
}
