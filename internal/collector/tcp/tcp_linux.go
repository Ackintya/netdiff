//go:build linux

package tcp

import (
	"net"

	"golang.org/x/sys/unix"
	"netdiff/pkg/model"
)

// getSocketInfo queries the Linux kernel TCP_INFO socket option via raw fd.
func getSocketInfo(conn net.Conn) *model.TCPSocketInfo {
	if conn == nil {
		return nil
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil
	}

	var info *model.TCPSocketInfo
	_ = rawConn.Control(func(fd uintptr) {
		tInfo, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil || tInfo == nil {
			return
		}

		info = &model.TCPSocketInfo{
			RTTUs:           tInfo.Rtt,
			RTTVarUs:        tInfo.Rttvar,
			MinRTTUs:        tInfo.Min_rtt,
			SndCwnd:         tInfo.Snd_cwnd,
			SndMSS:          tInfo.Snd_mss,
			RcvMSS:          tInfo.Rcv_mss,
			Retransmits:     tInfo.Retransmits,
			TotalRetrans:    tInfo.Total_retrans,
			Lost:            tInfo.Lost,
			Pmtu:            tInfo.Pmtu,
			DeliveryRateBps: tInfo.Delivery_rate,
			BytesSent:       tInfo.Bytes_sent,
			BytesRetrans:    tInfo.Bytes_retrans,
		}
	})

	return info
}
