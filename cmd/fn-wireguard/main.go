package main

import (
	"context"
	"flag"
	"fmt"
	"fn-wireguard/internal/app"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		log.Fatal(e)
	}
}
func run() error {
	var o app.Options
	var address, socket, cert, key string
	flag.StringVar(&o.DataDir, "data-dir", "data", "private state directory")
	flag.StringVar(&o.WebDir, "web-dir", "web/dist", "built frontend directory")
	flag.StringVar(&o.Mode, "mode", "development", "development or production")
	flag.StringVar(&o.AuthMode, "auth-mode", "local", "local or fnos")
	flag.StringVar(&o.BasePath, "base-path", "", "public URL prefix")
	flag.BoolVar(&o.SecureCookie, "secure-cookie", false, "require HTTPS session cookies")
	flag.StringVar(&address, "listen", "127.0.0.1:8787", "TCP listen address")
	flag.StringVar(&socket, "socket", "", "Unix socket (disables TCP)")
	flag.StringVar(&socket, "unix-socket", "", "alias for --socket")
	flag.StringVar(&cert, "tls-cert", "", "TLS certificate PEM")
	flag.StringVar(&key, "tls-key", "", "TLS private key PEM")
	flag.Parse()
	if o.Mode != "development" && o.Mode != "production" {
		return fmt.Errorf("invalid mode")
	}
	if o.AuthMode == "fnos" && socket == "" {
		return fmt.Errorf("fnos authentication requires Unix socket transport")
	}
	if (cert == "") != (key == "") {
		return fmt.Errorf("TLS certificate and key must be provided together")
	}
	if socket != "" && cert != "" {
		return fmt.Errorf("TLS flags are only supported for TCP")
	}
	if cert != "" {
		o.SecureCookie = true
	}
	o.BasePath = strings.TrimSuffix(o.BasePath, "/")
	if o.BasePath != "" && (!strings.HasPrefix(o.BasePath, "/") || strings.Contains(o.BasePath, "..") || strings.ContainsAny(o.BasePath, "?#\\\r\n")) {
		return fmt.Errorf("invalid base path")
	}
	var e error
	o.DataDir, e = filepath.Abs(o.DataDir)
	if e != nil {
		return e
	}
	o.WebDir, e = filepath.Abs(o.WebDir)
	if e != nil {
		return e
	}
	a, e := app.New(o)
	if e != nil {
		return e
	}
	defer func() {
		if e := a.Close(); e != nil {
			log.Printf("shutdown cleanup: %v", e)
		}
	}()
	var listener net.Listener
	if socket != "" {
		socket, e = filepath.Abs(socket)
		if e != nil {
			return e
		}
		if info, se := os.Lstat(socket); se == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return fmt.Errorf("socket path exists and is not a socket")
			}
			probe, pe := net.DialTimeout("unix", socket, time.Second)
			if pe == nil {
				probe.Close()
				return fmt.Errorf("socket is already in use")
			}
			if e = os.Remove(socket); e != nil {
				return e
			}
		} else if !os.IsNotExist(se) {
			return se
		}
		listener, e = net.Listen("unix", socket)
		if e == nil {
			e = os.Chmod(socket, 0600)
		}
		if e != nil {
			if listener != nil {
				listener.Close()
			}
			return e
		}
		defer os.Remove(socket)
	} else {
		listener, e = net.Listen("tcp", address)
		if e != nil {
			return e
		}
	}
	defer listener.Close()
	server := &http.Server{Handler: a, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(done)
	errCh := make(chan error, 1)
	go func() {
		if cert != "" {
			errCh <- server.ServeTLS(listener, cert, key)
		} else {
			errCh <- server.Serve(listener)
		}
	}()
	log.Printf("fn-wireguard started (mode=%s auth=%s)", o.Mode, o.AuthMode)
	select {
	case <-done:
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case e := <-errCh:
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	}
}
