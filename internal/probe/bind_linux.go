//go:build linux

package probe

import (
	"net"
	"syscall"
	"golang.org/x/sys/unix"
)

func setInterfaceControl(dialer *net.Dialer, ifaceName string) {
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.BindToDevice(int(fd), ifaceName)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
