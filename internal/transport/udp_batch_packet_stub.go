//go:build !linux

package transport

import (
	"errors"
	"net"
)

func NewUDPBatchPacketConn(*net.UDPConn, int, int) (UDPBatchPacket, error) {
	return nil, errors.New("udp batch: recvmmsg is available only on Linux")
}

func ListenUDPReusePort(string) (*net.UDPConn, error) {
	return nil, errors.New("udp batch: SO_REUSEPORT listener is available only on Linux")
}

func UDPBatchSupported() bool { return false }
