//go:build !linux

package maintenance

import "errors"

func Repair(path, username, groupname, serviceBinary string) error {
	return errors.New("maintenance is supported only on Linux")
}
