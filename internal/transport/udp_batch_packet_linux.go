//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type batchUDPAddr struct {
	remote *net.UDPAddr
	local  net.IP
}

func (a *batchUDPAddr) Network() string          { return a.remote.Network() }
func (a *batchUDPAddr) String() string           { return a.remote.String() }
func (a *batchUDPAddr) UDPAddress() *net.UDPAddr { return a.remote }

// UDPBatchPacketConn adapts recvmmsg-backed reads to net.PacketConn so the
// audited miekg/dns server retains parsing, TSIG, policy, and response behavior.
// Reads are single-consumer; writes remain safe for concurrent DNS handlers.
type UDPBatchPacketConn struct {
	conn    *net.UDPConn
	batch   *UDPBatchConn
	pending []UDPDatagram
	next    int
}

func NewUDPBatchPacketConn(conn *net.UDPConn, batchSize, packetSize int) (UDPBatchPacket, error) {
	batch, err := NewUDPBatchConn(conn, batchSize, packetSize)
	if err != nil {
		return nil, err
	}
	return &UDPBatchPacketConn{conn: conn, batch: batch}, nil
}

func (c *UDPBatchPacketConn) ReadFrom(destination []byte) (int, net.Addr, error) {
	for c.next >= len(c.pending) {
		batch, err := c.batch.ReadBatch()
		if err != nil {
			return 0, nil, err
		}
		c.pending = batch
		c.next = 0
	}
	datagram := c.pending[c.next]
	c.next++
	n := copy(destination, datagram.Payload)
	remote := *datagram.Addr
	remote.IP = append(net.IP(nil), datagram.Addr.IP...)
	return n, &batchUDPAddr{
		remote: &remote,
		local:  destinationIP(datagram.OOB),
	}, nil
}

func (c *UDPBatchPacketConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	if batchAddr, ok := destination.(*batchUDPAddr); ok {
		if batchAddr.local != nil {
			oob := sourceControlMessage(batchAddr.local)
			n, _, err := c.conn.WriteMsgUDP(payload, oob, batchAddr.remote)
			return n, err
		}
		return c.conn.WriteToUDP(payload, batchAddr.remote)
	}
	udpAddr, ok := destination.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("udp batch: unsupported destination %T", destination)
	}
	return c.conn.WriteToUDP(payload, udpAddr)
}

func (c *UDPBatchPacketConn) Close() error                       { return c.conn.Close() }
func (c *UDPBatchPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *UDPBatchPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *UDPBatchPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *UDPBatchPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *UDPBatchPacketConn) BatchStats() UDPBatchStats          { return c.batch.Stats() }

func ListenUDPReusePort(address string) (*net.UDPConn, error) {
	var controlErr error
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			if err := raw.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					controlErr = err
					return
				}
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", address)
	if err != nil {
		return nil, err
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, errors.New("udp batch: listener is not UDP")
	}
	return udpConn, nil
}

func UDPBatchSupported() bool { return true }

func destinationIP(oob []byte) net.IP {
	control6 := new(ipv6.ControlMessage)
	if control6.Parse(oob) == nil && control6.Dst != nil {
		return append(net.IP(nil), control6.Dst...)
	}
	control4 := new(ipv4.ControlMessage)
	if control4.Parse(oob) == nil && control4.Dst != nil {
		return append(net.IP(nil), control4.Dst...)
	}
	return nil
}

func sourceControlMessage(source net.IP) []byte {
	if source.To4() == nil {
		return (&ipv6.ControlMessage{Src: source}).Marshal()
	}
	return (&ipv4.ControlMessage{Src: source}).Marshal()
}
