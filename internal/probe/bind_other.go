//go:build !linux

package probe

import (
	"net"
)

func setInterfaceControl(_ *net.Dialer, _ string) {
	// Binding to specific interface device name is a Linux-specific socket option (SO_BINDTODEVICE)
}
