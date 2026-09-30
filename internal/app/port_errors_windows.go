package app

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"syscall"
)

func listenProbe(network, address string) (net.PacketConn, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionError error
		err := raw.Control(func(fd uintptr) {
			// Winsock defines SO_EXCLUSIVEADDRUSE as ~SO_REUSEADDR. Without
			// exclusive binding, a wildcard probe can miss a specific-IP listener.
			optionError = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, ^windows.SO_REUSEADDR, 1)
		})
		if err != nil {
			return err
		}
		return optionError
	}}
	return config.ListenPacket(context.Background(), network, address)
}

func portInUse(err error) bool { return errors.Is(err, windows.WSAEADDRINUSE) }
func ipv6Unavailable(err error) bool {
	return errors.Is(err, windows.WSAEAFNOSUPPORT) || errors.Is(err, windows.WSAEPROTONOSUPPORT) || errors.Is(err, windows.WSAEADDRNOTAVAIL)
}
