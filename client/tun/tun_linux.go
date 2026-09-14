//go:build linux

package tun

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// Having MTU at 1444 puts us at exactly 1500 bytes after all overhead (encryption, UDP headers, etc)
	MTU = 1444
	// Linux tun path
	tun = "/dev/net/tun"
)

// Configures the TUN interface with the specified tunnel name, specified address and maximum transferable unit size
func ConfigureTUN(
	tunnelName string,
	address string,
	mtu int,
) error {
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		return err
	}

	tunnelAddress, err := netlink.ParseAddr(address)
	if err != nil {
		return err
	}

	err = netlink.AddrReplace(link, tunnelAddress)
	if err != nil {
		return err
	}

	err = netlink.LinkSetMTU(link, mtu)
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	return nil
}

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
