package app

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndpointWithoutPortAndDNSValidation(t *testing.T) {
	for input, want := range map[string]string{
		"vpn.example.com":       "vpn.example.com:51820",
		" 192.0.2.10 ":          "192.0.2.10:51820",
		"2001:db8::1":           "[2001:db8::1]:51820",
		"[2001:db8::1]":         "[2001:db8::1]:51820",
		"vpn.example.com:12345": "vpn.example.com:12345",
		"[2001:db8::1]:12345":   "[2001:db8::1]:12345",
	} {
		s := defaultSettings()
		s.Endpoint = input
		s = normalizeSettings(s)
		if s.Endpoint != want || validateSettings(s) != nil {
			t.Fatalf("%q => %q, expected %q", input, s.Endpoint, want)
		}
	}
	for _, input := range []string{"https://vpn.example.com", "vpn.example.com/path", "vpn.example.com\n", "vpn.example.com:70000"} {
		s := defaultSettings()
		s.Endpoint = input
		if validateSettings(normalizeSettings(s)) == nil {
			t.Fatalf("accepted invalid endpoint %q", input)
		}
	}
	for _, dns := range []string{" ", ",", "192.168.1.1,", "auto", "192.168.1.1\n"} {
		s := defaultSettings()
		s.DNS = dns
		if validateSettings(s) == nil {
			t.Fatalf("accepted invalid DNS %q", dns)
		}
	}
}

func TestAutoDNSExportsWithoutOverride(t *testing.T) {
	private, public, err := privateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := runtimePeer{Peer: Peer{Address: "10.66.66.2/32"}, Private: private}
	s := defaultSettings()
	s.Endpoint = "vpn.example.com:51820"
	if s.DNS != "" {
		t.Fatal("new installation must default to automatic DNS")
	}
	for _, dns := range []string{"", "192.168.50.1, 2001:db8::53"} {
		s.DNS = dns
		config, err := clientConfig(s, p, public)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		_, hasDNS := parsed.Interface["dns"]
		if hasDNS != (dns != "") {
			t.Fatalf("incorrect DNS override for %q", dns)
		}
		if dns != "" && !strings.Contains(config, "DNS = "+dns+"\n") {
			t.Fatal("manual DNS was not preserved")
		}
	}
}

func TestClientSettingsSaveWhenRuntimeNotStopped(t *testing.T) {
	for _, state := range []string{"running", "unavailable", "unresolved"} {
		t.Run(state, func(t *testing.T) {
			a, err := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			a.options.Mode = "production"
			if state == "running" {
				a.adapter = &failingAdapter{running: true}
			}
			if state == "unresolved" {
				a.runtimeError = "runtime state unknown"
			}
			s, _, _, err := a.store.settings()
			if err != nil {
				t.Fatal(err)
			}
			s.Endpoint = "vpn.example.com"
			s.DNS = ""
			save := func(settings Settings) *httptest.ResponseRecorder {
				body, _ := json.Marshal(settings)
				w := httptest.NewRecorder()
				a.saveSettings(w, httptest.NewRequest("PUT", "/api/settings", strings.NewReader(string(body))))
				return w
			}
			if w := save(s); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			stored, _, _, err := a.store.settings()
			if err != nil || stored.Endpoint != "vpn.example.com:51820" || stored.DNS != "" {
				t.Fatal("settings were not persisted", stored, err)
			}
			view, err := a.overview()
			if err != nil {
				t.Fatal(err)
			}
			if view.(map[string]any)["server"].(map[string]any)["endpoint"] != stored.Endpoint {
				t.Fatal("overview did not reflect saved endpoint")
			}
			s.ListenPort++
			if w := save(s); w.Code != 409 {
				t.Fatal("live interface mutation accepted", w.Code, w.Body)
			}
		})
	}
}
