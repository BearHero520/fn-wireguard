package maintenance

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

var names = []string{"master.key", "state.db", "state.db-wal", "state.db-shm", "app.log", "bootstrap-token"}

type metadata struct {
	Regular bool
	Links   uint64
	Owner   uint32
	Size    int64
}

func validateFile(name string, m metadata, uid uint32) error {
	if !m.Regular {
		return fmt.Errorf("%s must be a regular file", name)
	}
	if m.Links != 1 {
		return fmt.Errorf("%s must have exactly one hard link", name)
	}
	if m.Owner != 0 && m.Owner != uid {
		return fmt.Errorf("%s has an unexpected owner", name)
	}
	if name == "master.key" && m.Size != 32 {
		return errors.New("master.key must be exactly 32 bytes; restore the original key from backup")
	}
	return nil
}
func validateSet(files map[string]metadata) error {
	_, database := files["state.db"]
	_, key := files["master.key"]
	if database && !key {
		return errors.New("state.db exists without master.key; restore the original key from backup")
	}
	_, wal := files["state.db-wal"]
	_, shm := files["state.db-shm"]
	if !database && (wal || shm) {
		return errors.New("SQLite recovery files exist without state.db; restore the original database from backup")
	}
	return nil
}
func validatePath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("data-dir must be an absolute path")
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) || clean == filepath.VolumeName(clean)+string(filepath.Separator) {
		return "", errors.New("data-dir cannot be a filesystem root")
	}
	if filepath.Base(clean) != "fn-wireguard" {
		return "", errors.New("data-dir must identify the fn-wireguard application directory")
	}
	return clean, nil
}

func matchesService(comm, exe, canonical string) bool {
	return strings.TrimSpace(comm) == "fn-wireguard" && strings.TrimSuffix(exe, " (deleted)") == canonical
}
