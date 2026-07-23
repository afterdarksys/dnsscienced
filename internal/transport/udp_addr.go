package transport

import "net"

type UDPBatchStats struct {
	ReadCalls          uint64
	Datagrams          uint64
	TruncatedDatagrams uint64
}

type UDPBatchStatser interface {
	BatchStats() UDPBatchStats
}

// UDPBatchPacket is the production batch adapter contract used by the server.
// Keeping the metrics method in the constructor's return type avoids reading
// miekg/dns's mutable PacketConn field to rediscover it after startup.
type UDPBatchPacket interface {
	net.PacketConn
	UDPBatchStatser
}

type udpAddressProvider interface {
	UDPAddress() *net.UDPAddr
}

// UDPAddress unwraps both ordinary UDP addresses and transport addresses that
// retain per-packet destination metadata for source-correct replies.
func UDPAddress(addr net.Addr) (*net.UDPAddr, bool) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr, true
	}
	if provider, ok := addr.(udpAddressProvider); ok {
		udpAddr := provider.UDPAddress()
		return udpAddr, udpAddr != nil
	}
	return nil, false
}
