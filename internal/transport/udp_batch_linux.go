//go:build linux

package transport

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	defaultUDPBatchSize = 64
	maxUDPBatchSize     = 256
	maxUDPDatagramSize  = 65535
)

type packetBatchConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

// UDPDatagram is one message in a Linux recvmmsg/sendmmsg batch. Payload aliases
// reusable receive storage and is valid only until the next ReadBatch call.
type UDPDatagram struct {
	Payload   []byte
	Addr      *net.UDPAddr
	Truncated bool
}

// UDPBatchConn wraps x/net's Linux recvmmsg/sendmmsg implementation with bounded,
// reusable packet slots. It is intended for one fixed worker; concurrent calls on
// the same UDPBatchConn are unsupported.
type UDPBatchConn struct {
	conn       *net.UDPConn
	packetConn packetBatchConn
	packetSize int
	storage    []byte
	recv       []ipv4.Message
	send       []ipv4.Message
	datagrams  []UDPDatagram
}

// NewUDPBatchConn prepares fixed receive/send descriptors for conn.
func NewUDPBatchConn(conn *net.UDPConn, batchSize, packetSize int) (*UDPBatchConn, error) {
	if conn == nil {
		return nil, errors.New("udp batch: nil connection")
	}
	if batchSize < 0 {
		return nil, errors.New("udp batch: negative batch size")
	}
	if batchSize == 0 {
		batchSize = defaultUDPBatchSize
	}
	if batchSize > maxUDPBatchSize {
		return nil, fmt.Errorf("udp batch: batch size %d exceeds maximum %d", batchSize, maxUDPBatchSize)
	}
	if packetSize <= 0 {
		packetSize = maxUDPDatagramSize
	}
	if packetSize > maxUDPDatagramSize {
		return nil, fmt.Errorf("udp batch: packet size %d exceeds UDP maximum", packetSize)
	}

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("udp batch: connection has no UDP local address")
	}

	var packets packetBatchConn
	if local.IP.To4() != nil {
		packets = ipv4.NewPacketConn(conn)
	} else {
		packets = ipv6.NewPacketConn(conn)
	}

	b := &UDPBatchConn{
		conn:       conn,
		packetConn: packets,
		packetSize: packetSize,
		storage:    make([]byte, batchSize*packetSize),
		recv:       make([]ipv4.Message, batchSize),
		send:       make([]ipv4.Message, batchSize),
		datagrams:  make([]UDPDatagram, batchSize),
	}
	for i := range b.recv {
		slot := b.storage[i*packetSize : (i+1)*packetSize]
		b.recv[i].Buffers = [][]byte{slot}
		b.send[i].Buffers = make([][]byte, 1)
	}
	return b, nil
}

// Capacity returns the maximum number of datagrams in one syscall.
func (b *UDPBatchConn) Capacity() int {
	return len(b.recv)
}

// ReadBatch receives up to Capacity datagrams with one recvmmsg call.
func (b *UDPBatchConn) ReadBatch() ([]UDPDatagram, error) {
	for i := range b.recv {
		b.recv[i].N = 0
		b.recv[i].NN = 0
		b.recv[i].Flags = 0
		b.recv[i].Addr = nil
	}

	n, err := b.packetConn.ReadBatch(b.recv, 0)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		addr, ok := b.recv[i].Addr.(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("udp batch: unexpected source address %T", b.recv[i].Addr)
		}
		length := b.recv[i].N
		if length > b.packetSize {
			length = b.packetSize
		}
		b.datagrams[i] = UDPDatagram{
			Payload:   b.recv[i].Buffers[0][:length:length],
			Addr:      addr,
			Truncated: b.recv[i].Flags&unix.MSG_TRUNC != 0,
		}
	}
	return b.datagrams[:n], nil
}

// WriteBatch sends datagrams with one sendmmsg call. A partial count is returned
// when the kernel accepts only part of the batch.
func (b *UDPBatchConn) WriteBatch(datagrams []UDPDatagram) (int, error) {
	if len(datagrams) == 0 {
		return 0, nil
	}
	if len(datagrams) > len(b.send) {
		return 0, fmt.Errorf("udp batch: %d datagrams exceed capacity %d", len(datagrams), len(b.send))
	}
	for i := range datagrams {
		if len(datagrams[i].Payload) == 0 {
			return 0, errors.New("udp batch: empty datagram")
		}
		if datagrams[i].Addr == nil {
			return 0, errors.New("udp batch: nil destination")
		}
		b.send[i].Buffers[0] = datagrams[i].Payload
		b.send[i].Addr = datagrams[i].Addr
		b.send[i].N = 0
		b.send[i].NN = 0
		b.send[i].Flags = 0
	}
	return b.packetConn.WriteBatch(b.send[:len(datagrams)], 0)
}
