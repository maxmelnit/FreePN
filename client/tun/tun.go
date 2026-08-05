//go:build linux

package tun

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// Ethernet maximum transmission unit is 1500 bytes
	MTU = 1500
	// Linux tun path
	tun = "/dev/net/tun"
)

func OpenTUN(tunnelName string) (*os.File, error) {
	rawFD, err := unix.Open(
		tun,
		unix.O_RDWR|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}

	var ifreq [40]byte
	copy(ifreq[:16], tunnelName)
	*(*uint16)(unsafe.Pointer(&ifreq[16])) =
		unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(rawFD),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifreq[0])),
	)

	if errno != 0 {
		unix.Close(rawFD)
		return nil, errno
	}

	// Wrap it only after TUNSETIFF has attached the interface.
	return os.NewFile(uintptr(rawFD), tun), nil
}
