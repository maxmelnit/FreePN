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

func OpenTUN() (*os.File, error) {

	// Try opening the tun path accesses the virtual interface
	fd, err := os.OpenFile(tun, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	// Kernel written in C, so we need to mimic ifreq struct used to configure network interface, which is 40 bytes long
	var ifreq [40]byte
	copy(ifreq[:16], "freepn-tun") // First 16 bytes is char ifr_name
	*(*uint16)(unsafe.Pointer(&ifreq[16])) = unix.IFF_TUN | unix.IFF_NO_PI

	// Make system call to create the interface
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,       // Tells kernel this is an IOCTL call
		fd.Fd(),                 // Give the kernel the tun descriptor
		uintptr(unix.TUNSETIFF), // Set interface name and flags
		uintptr(unsafe.Pointer(&ifreq[0])),
	)

	if errno != 0 {
		fd.close()
	}

}
