// Normalize Linux permissions after the official Windows fnpack build.
// The official tool maps Windows regular files to non-executable TAR modes.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type entry struct {
	header tar.Header
	body   []byte
}

func readArchive(data []byte) ([]entry, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var result []entry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		result = append(result, entry{*h, b})
	}
	return result, nil
}
func writeArchive(entries []entry) ([]byte, error) {
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		e.header.Size = int64(len(e.body))
		if err := tw.WriteHeader(&e.header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func normalize(entries []entry, inner bool) {
	for i := range entries {
		e := &entries[i]
		name := strings.TrimPrefix(e.header.Name, "./")
		e.header.Uid = 0
		e.header.Gid = 0
		e.header.Uname = "root"
		e.header.Gname = "root"
		if e.header.Typeflag == tar.TypeDir {
			e.header.Mode = 0755
			continue
		}
		if e.header.Typeflag != tar.TypeReg {
			continue
		}
		e.header.Mode = 0644
		if (!inner && strings.HasPrefix(name, "cmd/")) || (inner && (name == "server/fn-wireguard" || name == "server/fn-wireguard-maintenance" || name == "server/run-service" || name == "server/prepare-data")) {
			e.header.Mode = 0755
		}
	}
}
func run(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	outer, err := readArchive(data)
	if err != nil {
		return err
	}
	appIndex, manifestIndex := -1, -1
	for i, e := range outer {
		switch strings.TrimPrefix(e.header.Name, "./") {
		case "app.tgz":
			appIndex = i
		case "manifest":
			manifestIndex = i
		}
	}
	if appIndex < 0 || manifestIndex < 0 {
		return fmt.Errorf("unsupported FPK: app.tgz/manifest missing")
	}
	inner, err := readArchive(outer[appIndex].body)
	if err != nil {
		return err
	}
	normalize(inner, true)
	appData, err := writeArchive(inner)
	if err != nil {
		return err
	}
	outer[appIndex].body = appData
	sum := fmt.Sprintf("%x", md5.Sum(appData))
	checksum := regexp.MustCompile(`(?m)^checksum\s*=\s*[0-9a-fA-F]{32}`)
	if !checksum.Match(outer[manifestIndex].body) {
		return fmt.Errorf("unsupported FPK manifest checksum format")
	}
	outer[manifestIndex].body = checksum.ReplaceAll(outer[manifestIndex].body, []byte("checksum = "+sum))
	normalize(outer, false)
	final, err := writeArchive(outer)
	if err != nil {
		return err
	}
	temp := path + ".permissions.tmp"
	if err = os.WriteFile(temp, final, 0600); err != nil {
		return err
	}
	defer os.Remove(temp)
	// Replace only the build artifact supplied by the caller.
	return os.Rename(temp, path)
}
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fpk-permissions <fpk>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
