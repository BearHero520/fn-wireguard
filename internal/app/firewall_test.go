package app

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Reduced from the NAS's nftables 1.0.6 read-only output: the table's
// ownership comment exists in text but is absent from JSON.
const legacyTableJSON = `{"nftables":[{"table":{"family":"inet","name":"fnwg_access","handle":10}}]}`
const legacyTableText = `table inet fnwg_access { # handle 10
	comment "fn-wireguard-managed-v1"
	chain input { # handle 1
		type filter hook input priority filter - 10; policy accept;
		iifname "fnwg0" counter drop # handle 15
	}
}
`

func TestFirewallLegacyOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, snapshot, text string
		wantOK, wantRead     bool
	}{
		{"1.0.6 table", legacyTableJSON, legacyTableText, true, true},
		{"modern JSON", strings.Replace(legacyTableJSON, `"handle":10`, `"handle":10,"comment":"fn-wireguard-managed-v1"`, 1), "", true, false},
		{"explicit foreign comment", strings.Replace(legacyTableJSON, `"handle":10`, `"handle":10,"comment":"foreign"`, 1), legacyTableText, false, false},
		{"explicit empty comment", strings.Replace(legacyTableJSON, `"handle":10`, `"handle":10,"comment":""`, 1), legacyTableText, false, false},
		{"foreign table", legacyTableJSON, strings.Replace(legacyTableText, ownership, "foreign", 1), false, true},
		{"handle changed between reads", legacyTableJSON, strings.Replace(legacyTableText, "handle 10", "handle 11", 1), false, true},
		{"wrong table", legacyTableJSON, strings.Replace(legacyTableText, accessTable, "other", 1), false, true},
		{"wrong family", legacyTableJSON, strings.Replace(legacyTableText, "table inet", "table ip", 1), false, true},
		{"chain comment only", legacyTableJSON, "table inet fnwg_access { # handle 10\n\tchain input {\n\t\tcomment \"fn-wireguard-managed-v1\"\n\t}\n}\n", false, true},
		{"rule comment only", legacyTableJSON, "table inet fnwg_access { # handle 10\n\tchain input {\n\t\taccept comment \"fn-wireguard-managed-v1\"\n\t}\n}\n", false, true},
		{"unmarked empty table", legacyTableJSON, "table inet fnwg_access { # handle 10\n}\n", false, true},
		{"zero handle", strings.Replace(legacyTableJSON, `"handle":10`, `"handle":0`, 1), legacyTableText, false, true},
		{"missing text", legacyTableJSON, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			plan, err := firewallPlan([]byte(tc.snapshot), Settings{}, nil, func() ([]byte, error) {
				reads++
				return []byte(tc.text), nil
			})
			if (err == nil) != tc.wantOK || (reads > 0) != tc.wantRead {
				t.Fatal("unexpected ownership result", err, reads)
			}
			if tc.wantOK && plan != "delete table inet handle 10\n" || !tc.wantOK && plan != "" {
				t.Fatal("unsafe cleanup plan", plan)
			}
		})
	}
}

func TestFirewallLegacyApplyUpdateStop(t *testing.T) {
	handle, writes := 0, 0
	run := func(input string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-j list ruleset":
			if handle == 0 {
				return []byte(`{"nftables":[]}`), nil
			}
			return []byte(fmt.Sprintf(`{"nftables":[{"table":{"family":"inet","name":"fnwg_access","handle":%d}}]}`, handle)), nil
		case "-s -a list table inet fnwg_access":
			return []byte(strings.Replace(legacyTableText, "handle 10", fmt.Sprintf("handle %d", handle), 1)), nil
		case "-f -":
			writes++
			if handle != 0 && !strings.HasPrefix(input, fmt.Sprintf("delete table inet handle %d\n", handle)) {
				t.Fatal("update did not target the verified table", input)
			}
			if strings.Contains(input, "create table inet fnwg_access") {
				handle = writes + 9
			} else {
				handle = 0
			}
			return nil, nil
		default:
			t.Fatal("unexpected nft command", args)
			return nil, nil
		}
	}
	peer := runtimePeer{Peer: Peer{Address: "10.66.66.2/32", Enabled: true}}
	if err := applyFirewallRules(lanSettings(), []runtimePeer{peer}, run); err != nil {
		t.Fatal("initial start", err)
	}
	peer.AccessMode, peer.AllowedDevices = "selected", []string{"192.168.50.10"}
	if err := applyFirewallRules(lanSettings(), []runtimePeer{peer}, run); err != nil {
		t.Fatal("live access update", err)
	}
	if err := applyFirewallRules(Settings{}, nil, run); err != nil {
		t.Fatal("stop cleanup", err)
	}
	if err := applyFirewallRules(Settings{}, nil, run); err != nil || handle != 0 || writes != 3 {
		t.Fatal("repeated stop", err, handle, writes)
	}
}

func TestFirewallPreflightFailureDoesNotWrite(t *testing.T) {
	for _, stage := range []string{"snapshot", "text", "ownership", "transaction"} {
		t.Run(stage, func(t *testing.T) {
			writes := 0
			err := applyFirewallRules(lanSettings(), nil, func(input string, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "-j list ruleset":
					if stage == "snapshot" {
						return nil, errors.New("cannot read snapshot")
					}
					return []byte(legacyTableJSON), nil
				case "-s -a list table inet fnwg_access":
					if stage == "text" {
						return nil, errors.New("cannot read table")
					}
					if stage == "ownership" {
						return []byte(strings.Replace(legacyTableText, ownership, "foreign", 1)), nil
					}
					return []byte(legacyTableText), nil
				case "-f -":
					writes++
					return nil, errors.New("transaction failed or timed out")
				default:
					t.Fatal(args)
					return nil, nil
				}
			})
			var unchanged *runtimeUnchangedError
			if err == nil || errors.As(err, &unchanged) != (stage != "transaction") || (writes == 0) != (stage != "transaction") {
				t.Fatal("incorrect mutation classification", err, writes)
			}
		})
	}
}

type sequenceAdapter struct {
	failingAdapter
	errors []error
}

func (f *sequenceAdapter) Apply(Settings, string, []runtimePeer) error {
	i := f.applies
	f.applies++
	if i < len(f.errors) {
		return f.errors[i]
	}
	return nil
}

func TestRuntimeRecoveryState(t *testing.T) {
	failed := errors.New("apply failed")
	preflight := &runtimeUnchangedError{errors.New("ownership check failed")}
	for _, tc := range []struct {
		name   string
		errors []error
		calls  int
		locked bool
	}{
		{"preflight", []error{preflight}, 1, false},
		{"restored", []error{failed, nil}, 2, false},
		{"rollback failed", []error{failed, failed}, 2, true},
		{"rollback preflight failed", []error{failed, preflight}, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(Options{DataDir: t.TempDir(), Mode: "development", AuthMode: "fnos"})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			f := &sequenceAdapter{failingAdapter: failingAdapter{running: true}, errors: tc.errors}
			a.adapter, a.options.Mode = f, "production"
			if changed, err := a.mutateRuntime(nil, nil); changed || err == nil || f.applies != tc.calls || (a.runtimeError != "") != tc.locked {
				t.Fatal("incorrect failure state", changed, err, f.applies, a.runtimeError)
			}
			_, err = a.mutateRuntime(nil, nil)
			if tc.locked {
				if err == nil || !strings.Contains(err.Error(), "runtime state is unresolved") || f.applies != tc.calls {
					t.Fatal("uncertain runtime allowed another update", err, f.applies)
				}
			} else if err != nil || f.applies != tc.calls+1 {
				t.Fatal("safe retry was blocked", err, f.applies)
			}
		})
	}
}

// Optional real read-only NAS snapshots can exercise exactly the production
// planner locally and export scripts for nft --check (never apply them here).
func TestFirewallNASReadOnlySnapshot(t *testing.T) {
	prefix := os.Getenv("FNWG_NFT_SNAPSHOT_PREFIX")
	if prefix == "" {
		t.Skip("no read-only NAS snapshot supplied")
	}
	raw, err := os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal(err)
	}
	readTable := func() ([]byte, error) { return os.ReadFile(prefix + ".txt") }
	peer := runtimePeer{Peer: Peer{Address: "10.66.66.2/32", Enabled: true, AccessMode: "selected", AllowedDevices: []string{"192.168.50.10"}}}
	for _, mode := range []string{"update", "stop"} {
		s := lanSettings()
		if mode == "stop" {
			s = Settings{}
		}
		plan, err := firewallPlan(raw, s, []runtimePeer{peer}, readTable)
		if err != nil {
			t.Fatal(mode, err)
		}
		if err = os.WriteFile(prefix+"-"+mode+".nft", []byte(plan), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
