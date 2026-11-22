//go:build !linux

package tcp

import (
	"net"

	"netdiff/pkg/model"
)

// getSocketInfo is a no-op fallback for non-Linux operating systems where TCP_INFO is unavailable.
func getSocketInfo(conn net.Conn) *model.TCPSocketInfo {
	return nil
}
