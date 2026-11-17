//go:build linux

package probe

import (
	"golang.org/x/sys/unix"
	"net"
	"syscall"
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
