package cli

import (
	"syscall"
	"unsafe"
)

func isTerminalFD(fd uintptr) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGETA, uintptr(unsafe.Pointer(&termios)))
	return err == 0
}
