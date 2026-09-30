//go:build linux

package maintenance

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Repair changes only metadata through verified file descriptors. It never
// reads, recreates, deletes, or transforms encryption keys or SQLite contents.
func Repair(path, username, groupname, serviceBinary string) error {
	if os.Geteuid() != 0 {
		return errors.New("maintenance requires Linux root")
	}
	path, e := validatePath(path)
	if e != nil {
		return e
	}
	if !filepath.IsAbs(serviceBinary) || filepath.Base(serviceBinary) != "fn-wireguard" {
		return errors.New("service-binary must be an absolute fn-wireguard executable path")
	}
	canonical, e := filepath.EvalSymlinks(serviceBinary)
	if e != nil {
		return fmt.Errorf("resolve service binary: %w", e)
	}
	if e = ensureStopped(canonical); e != nil {
		return e
	}
	account, e := user.Lookup(username)
	if e != nil {
		return fmt.Errorf("resolve service user: %w", e)
	}
	group, e := user.LookupGroup(groupname)
	if e != nil {
		return fmt.Errorf("resolve service group: %w", e)
	}
	uid, e := strconv.ParseUint(account.Uid, 10, 32)
	if e != nil || uid == 0 {
		return errors.New("service user must have a valid nonzero UID")
	}
	gid, e := strconv.ParseUint(group.Gid, 10, 32)
	if e != nil {
		return errors.New("service group has an invalid GID")
	}
	info, e := os.Lstat(path)
	if e != nil {
		return fmt.Errorf("inspect existing data directory: %w", e)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("data-dir must be an existing directory, never a symbolic link")
	}
	dir, e := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return fmt.Errorf("open data directory without following links: %w", e)
	}
	defer unix.Close(dir)
	var directory unix.Stat_t
	if e = unix.Fstat(dir, &directory); e != nil {
		return fmt.Errorf("stat data directory descriptor: %w", e)
	}
	if directory.Uid != 0 && directory.Uid != uint32(uid) {
		return errors.New("data directory has an unexpected owner")
	}
	sealed := true
	defer func() {
		if sealed {
			unix.Fchown(dir, 0, 0)
			unix.Fchmod(dir, 0700)
		}
	}()
	if e = unix.Fchown(dir, 0, 0); e != nil {
		return fmt.Errorf("cannot seal data directory ownership: %w", e)
	}
	if e = unix.Fchmod(dir, 0700); e != nil {
		return fmt.Errorf("cannot seal data directory permissions: %w", e)
	}
	files := map[string]metadata{}
	descriptors := map[string]int{}
	defer func() {
		for _, fd := range descriptors {
			unix.Close(fd)
		}
	}()
	for _, name := range names {
		var entry unix.Stat_t
		e = unix.Fstatat(dir, name, &entry, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(e, unix.ENOENT) {
			continue
		}
		if e != nil {
			return fmt.Errorf("inspect %s; directory remains root-private: %w", name, e)
		}
		m := metadata{entry.Mode&unix.S_IFMT == unix.S_IFREG, uint64(entry.Nlink), entry.Uid, entry.Size}
		if e = validateFile(name, m, uint32(uid)); e != nil {
			return fmt.Errorf("validation failed; directory remains root-private: %w", e)
		}
		fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s; directory remains root-private: %w", name, err)
		}
		descriptors[name] = fd
		var actual unix.Stat_t
		if e = unix.Fstat(fd, &actual); e != nil {
			return fmt.Errorf("stat %s descriptor: %w", name, e)
		}
		if actual.Dev != entry.Dev || actual.Ino != entry.Ino {
			return fmt.Errorf("%s changed during validation; directory remains root-private", name)
		}
		m = metadata{actual.Mode&unix.S_IFMT == unix.S_IFREG, uint64(actual.Nlink), actual.Uid, actual.Size}
		if e = validateFile(name, m, uint32(uid)); e != nil {
			return e
		}
		files[name] = m
	}
	if e = validateSet(files); e != nil {
		return fmt.Errorf("validation failed; directory remains root-private: %w", e)
	}
	// Validate every file before changing any file owner. The sealed directory
	// prevents the unprivileged service from replacing checked entries.
	for _, name := range names {
		fd, exists := descriptors[name]
		if !exists {
			continue
		}
		if e = unix.Fchown(fd, int(uid), int(gid)); e != nil {
			return fmt.Errorf("change %s owner; directory remains root-private: %w", name, e)
		}
		if e = unix.Fchmod(fd, 0600); e != nil {
			return fmt.Errorf("change %s permissions; directory remains root-private: %w", name, e)
		}
	}
	if e = unix.Fchmod(dir, 0700); e != nil {
		return fmt.Errorf("finalize data directory permissions: %w", e)
	}
	if e = unix.Fchown(dir, int(uid), int(gid)); e != nil {
		return fmt.Errorf("finalize data directory owner: %w", e)
	}
	sealed = false
	return nil
}

func ensureStopped(canonical string) error {
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return fmt.Errorf("inspect running services: %w", e)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, e := strconv.ParseUint(entry.Name(), 10, 32); e != nil {
			continue
		}
		base := filepath.Join("/proc", entry.Name())
		comm, e := os.ReadFile(filepath.Join(base, "comm"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return fmt.Errorf("inspect process identity: %w", e)
		}
		if strings.TrimSpace(string(comm)) != "fn-wireguard" {
			continue
		}
		exe, e := os.Readlink(filepath.Join(base, "exe"))
		if os.IsNotExist(e) {
			if _, gone := os.Stat(base); os.IsNotExist(gone) {
				continue
			}
			return errors.New("cannot verify a remaining fn-wireguard candidate; stop the service before maintenance")
		}
		if e != nil {
			return fmt.Errorf("cannot verify a running fn-wireguard candidate; stop the service before maintenance: %w", e)
		}
		if matchesService(string(comm), exe, canonical) {
			return errors.New("the application service is still running; stop it before maintenance")
		}
	}
	return nil
}
