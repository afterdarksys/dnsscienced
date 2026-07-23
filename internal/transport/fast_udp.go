package transport

import (
	"context"
	"net"
	"sync/atomic"

	dnsasm "github.com/dnsscience/dnsscienced/dnsasm/go"
	"github.com/dnsscience/dnsscienced/internal/engine"
	"github.com/miekg/dns"
)

// FastUDPServer handles DNS requests/responses using high-performance socket options
// and assembly-optimized parsing.
type FastUDPServer struct {
	addr       string
	conn       *net.UDPConn
	resolver   *engine.Resolver
	workerPool int // Number of generic listeners is handled by OS via SO_REUSEPORT
	done       chan struct{}

	// Statistics (Atomic)
	packetsRecv   uint64
	packetsSent   uint64
	packErrors    uint64
	backendErrors uint64

	// Stats mutex removed in favor of atomics
}

// NewFastUDPServer creates a new optimized UDP server
func NewFastUDPServer(addr string, resolver *engine.Resolver, workers int) *FastUDPServer {
	return &FastUDPServer{
		addr:       addr,
		resolver:   resolver,
		workerPool: workers,
		done:       make(chan struct{}),
	}
}

// Start spawns multiple listeners (SO_REUSEPORT must be enabled in listener config if multiple processes,
// but here we spawn goroutines sharing connection or creating multiple connections if OS allows.
// To keep it simple and portable, we'll use a single connection with multiple worker routines reading in parallel if supported,
// or just simple read-loop.
// For 4M QPS, we usually need multiple read-queues.
// This implementation assumes 'conn' is shared or handled elsewhere.
// For this rewrite, we create the listener.
func (s *FastUDPServer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn

	// Set large buffers
	if err := s.conn.SetReadBuffer(4 * 1024 * 1024); err != nil {
		// Just log error but continue
	}
	if err := s.conn.SetWriteBuffer(4 * 1024 * 1024); err != nil {
		// Just log error
	}

	for i := 0; i < s.workerPool; i++ {
		go s.worker()
	}

	return nil
}

func (s *FastUDPServer) Stop() {
	close(s.done)
	if s.conn != nil {
		s.conn.Close()
	}
}

// Stats returns current statistics safely
func (s *FastUDPServer) Stats() map[string]uint64 {
	return map[string]uint64{
		"recv":    atomic.LoadUint64(&s.packetsRecv),
		"sent":    atomic.LoadUint64(&s.packetsSent),
		"err_fmt": atomic.LoadUint64(&s.packErrors),
		"err_res": atomic.LoadUint64(&s.backendErrors),
	}
}

func (s *FastUDPServer) worker() {
	// Reusable buffer per worker
	buf := make([]byte, 65535)

	// Context for this worker
	ctx := context.Background()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			// Check if closed
			continue
		}

		atomic.AddUint64(&s.packetsRecv, 1)

		// Process packet synchronously in worker to avoid goroutine churn
		// "Zero-Copy": pass slice of buffer.
		s.handlePacket(ctx, buf[:n], addr)
	}
}

func (s *FastUDPServer) handlePacket(ctx context.Context, packet []byte, addr *net.UDPAddr) {
	// 1. Parse the fixed header without allocating or crossing cgo.
	var header dnsasm.Header
	err := dnsasm.ParseHeaderInto(packet, &header)
	if err != nil {
		atomic.AddUint64(&s.packErrors, 1)
		return
	}

	// Only process queries
	if header.QR {
		return
	}

	// 2. Parse Question
	// dnsasm.ParseQuestion parses the question section and returns the Question struct and new offset
	question, offset, err := dnsasm.ParseQuestion(packet, 12) // Header is always 12 bytes
	if err != nil {
		s.sendFormatError(packet, header.ID, addr)
		return
	}

	// 3. Fast Check for EDNS0 (Opt Record)
	// We avoid miekg/dns.Unpack here.
	hasEDNS0 := false

	// If Additional Records exist, scan for OPT (Type 41)
	// We assume standard query structure: Header + Question + [Authority] + [Additional]
	// If ANCount or NSCount > 0, we might strictly need to skip them, but usually they are 0 for queries.
	if header.ARCount > 0 && header.ANCount == 0 && header.NSCount == 0 {
		// Scan from 'offset'
		// OPT record Name is usually root (0).
		// We peek at the next bytes.
		current := offset
		if current < len(packet) {
			// Simple scanner: expect root label (0)
			if packet[current] == 0 {
				current++
				// Next 2 bytes are Type
				if current+2 <= len(packet) {
					// OPT is type 41 (0x0029)
					// Big endian check
					if packet[current] == 0x00 && packet[current+1] == 0x29 {
						hasEDNS0 = true
					}
				}
			}
			// If not root, it might be TSIG or something else. We assume standard EDNS Opt is first
		}
	} else if (header.ANCount > 0 || header.NSCount > 0) && header.ARCount > 0 {
		// Fallback to slow path if structure is complex (rare for queries)
		dnsReq := new(dns.Msg)
		if err := dnsReq.Unpack(packet); err == nil {
			if dnsReq.IsEdns0() != nil {
				hasEDNS0 = true
			}
		}
	}

	// 4. Resolve using Resolver.ResolveRaw (Zero-Copy-ish)
	result, err := s.resolver.ResolveRaw(
		ctx,
		question.Name, // Pre-parsed string from dnsasm
		question.Type,
		question.Class,
		hasEDNS0,
	)

	if err != nil {
		atomic.AddUint64(&s.backendErrors, 1)
		s.sendServerFailure(header.ID, addr)
		return
	}

	// 5. Send Response
	// The result.Wire contains the packed response bytes from upstream/cache
	// We just rewrite the ID to match the request ID
	// Note: ResolveRaw returns bytes ready to send, but we must ensure ID matches.
	// We assume upstream preserves ID or we patch it.
	// Since we use miekg/dns client, it might change ID? No, client handles matching.
	// But valid response to CLIENT needs CLIENT's ID.
	// ResolveRaw returns 'in.Unpack() -> ...'. ID is from upstream response.
	// We MUST patch the ID.

	if len(result.Wire) >= 2 {
		result.Wire[0] = byte(header.ID >> 8)
		result.Wire[1] = byte(header.ID)
	}

	if _, err := s.conn.WriteToUDP(result.Wire, addr); err != nil {
		atomic.AddUint64(&s.packErrors, 1)
		return
	}

	atomic.AddUint64(&s.packetsSent, 1)
}

func (s *FastUDPServer) sendFormatError(req []byte, id uint16, addr *net.UDPAddr) {
	// Minimal error response
	resp := new(dns.Msg)
	resp.SetRcodeFormatError(&dns.Msg{MsgHdr: dns.MsgHdr{Id: id}})
	buf, _ := resp.Pack()
	s.conn.WriteToUDP(buf, addr)
}

func (s *FastUDPServer) sendServerFailure(id uint16, addr *net.UDPAddr) {
	resp := new(dns.Msg)
	resp.Id = id
	resp.Response = true
	resp.Rcode = dns.RcodeServerFailure
	buf, _ := resp.Pack()
	s.conn.WriteToUDP(buf, addr)
}
