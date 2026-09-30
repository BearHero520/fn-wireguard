package main

import (
	"flag"
	"fmt"
	"fn-wireguard/internal/maintenance"
	"os"
)

func main() {
	var path, username, group, serviceBinary string
	flag.StringVar(&path, "data-dir", "", "absolute existing data directory")
	flag.StringVar(&username, "user", "fnwireguard", "service account name")
	flag.StringVar(&group, "group", "fnwireguard", "service group name")
	flag.StringVar(&serviceBinary, "service-binary", "", "absolute service executable path (required)")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "maintenance: unexpected positional arguments")
		os.Exit(1)
	}
	if e := maintenance.Repair(path, username, group, serviceBinary); e != nil {
		fmt.Fprintln(os.Stderr, "maintenance:", e)
		os.Exit(1)
	}
}
