//go:build !windows

package app

import (
	"errors"
	"net"
	"syscall"
)

func listenProbe(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func portInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
func ipv6Unavailable(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)
}
