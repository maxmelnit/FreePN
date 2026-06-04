//go:build linux

package tun

import (
	"os"
	"syscall"
)

const (
	// Ethernet maximum transmission unit is 1500 bytes
	MTU = 1500
	// Linux tun path
	tun = "/dev/net/tun"
)

func OpenTUN() (*os.File, error) {

	// Try opening the tun path accesses the virtual interface
	fd, err := os.OpenFile(tun, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	// Make system call to create the interface
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, // Tells kernel this is an IOCTL call
		fd.Fd(),           // Give the kernel
	)

	if errno != 0 {
		fd.close()
	}

}
