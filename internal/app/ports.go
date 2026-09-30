package app

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

type portCheck struct {
	Port       int    `json:"port"`
	ActualPort int    `json:"actualPort"`
	State      string `json:"state"`
	Detail     string `json:"detail,omitempty"`
	CheckedAt  string `json:"checkedAt"`
}

// A bind probe checks the application's network namespace without sending any
// packets. Keep both sockets until the check completes; close them immediately.
// Availability is a snapshot, not a reservation or a WAN connectivity test.
func probeUDP(port int) (string, string) {
	for _, network := range []string{"udp4", "udp6"} {
		address := "0.0.0.0"
		if network == "udp6" {
			address = "::"
		}
		conn, err := listenProbe(network, net.JoinHostPort(address, strconv.Itoa(port)))
		if err != nil {
			if portInUse(err) {
				return "in-use", ""
			}
			if network == "udp6" && ipv6Unavailable(err) {
				continue
			}
			return "unknown", fmt.Sprintf("cannot check %s port: %v", network, err)
		}
		defer conn.Close()
	}
	return "available", ""
}

func inspectPort(port int, status RuntimeStatus, probe func(int) (string, string)) portCheck {
	result := portCheck{Port: port, ActualPort: status.ListenPort, CheckedAt: time.Now().UTC().Format(time.RFC3339), State: "unknown"}
	if status.Reason != "" || !status.Available {
		result.Detail = status.Reason
		return result
	}
	if status.Running && status.ListenPort == port {
		result.State = "active"
		return result
	}
	result.State, result.Detail = probe(port)
	return result
}

func (a *App) checkPort(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Port int `json:"port"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if body.Port < 1 || body.Port > 65535 {
		fail(w, 400, "listen port must be 1–65535")
		return
	}
	status := a.adapter.Status()
	if a.runtimeError != "" {
		status.Reason = a.runtimeError
	}
	respond(w, 200, inspectPort(body.Port, status, probeUDP))
}
