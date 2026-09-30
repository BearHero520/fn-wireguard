package maintenance

import (
	"path/filepath"
	"testing"
)

func TestStrictMetadataValidation(t *testing.T) {
	valid := metadata{Regular: true, Links: 1, Owner: 1234, Size: 32}
	if e := validateFile("master.key", valid, 1234); e != nil {
		t.Fatal(e)
	}
	root := valid
	root.Owner = 0
	if e := validateFile("state.db", root, 1234); e != nil {
		t.Fatal(e)
	}
	for _, m := range []metadata{{Regular: false, Links: 1, Owner: 1234, Size: 32}, {Regular: true, Links: 2, Owner: 1234, Size: 32}, {Regular: true, Links: 1, Owner: 99, Size: 32}, {Regular: true, Links: 1, Owner: 1234, Size: 31}} {
		if e := validateFile("master.key", m, 1234); e == nil {
			t.Fatal("unsafe metadata accepted", m)
		}
	}
}
func TestDatabaseRequiresOriginalKey(t *testing.T) {
	if e := validateSet(map[string]metadata{"state.db": {}}); e == nil {
		t.Fatal("database without original key accepted")
	}
	if e := validateSet(map[string]metadata{"state.db": {}, "master.key": {}}); e != nil {
		t.Fatal(e)
	}
	if e := validateSet(map[string]metadata{}); e != nil {
		t.Fatal("fresh empty directory rejected")
	}
	for _, name := range []string{"state.db-wal", "state.db-shm"} {
		if e := validateSet(map[string]metadata{name: {}}); e == nil {
			t.Fatal("orphan SQLite recovery file accepted")
		}
	}
}
func TestMaintenancePathValidation(t *testing.T) {
	if _, e := validatePath("relative"); e == nil {
		t.Fatal("relative path accepted")
	}
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	if _, e := validatePath(root); e == nil {
		t.Fatal("filesystem root accepted")
	}
	if _, e := validatePath(filepath.Join(t.TempDir(), "fn-wireguard")); e != nil {
		t.Fatal(e)
	}
	if _, e := validatePath(t.TempDir()); e == nil {
		t.Fatal("unrelated application path accepted")
	}
}

func TestServiceProcessIdentification(t *testing.T) {
	path := filepath.Join(string(filepath.Separator), "apps", "fn-wireguard", "server", "fn-wireguard")
	if !matchesService("fn-wireguard\n", path, path) || !matchesService("fn-wireguard\n", path+" (deleted)", path) {
		t.Fatal("live or replaced service not detected")
	}
	if matchesService("unrelated", path, path) || matchesService("fn-wireguard", path+"-other", path) {
		t.Fatal("unrelated process identified as service")
	}
}
