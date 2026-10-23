package telegramv2

import (
	"errors"
	"os"
	"syscall"
)

// Stable sidecar survives protectedWrite's session inode replacement. All local
// inventory/native users share it; cross-host copies require operator exclusion.
func lockSession(path string) (func(), error) {
	if e := protectedPath(path, false); e != nil {
		return nil, e
	}
	lockPath := path + ".lock"
	if e := protectedPath(lockPath, false); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, errors.New("protected session lock unavailable")
	}
	f := os.NewFile(uintptr(fd), lockPath)
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("session lock requires regular mode0600 file")
	}
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("Telegram session is already in use")
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }, nil
}
