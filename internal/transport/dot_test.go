package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoTHandleConnectionSupportsPipelinedQueries(t *testing.T) {
	listener := &DoTListener{
		timeout: time.Second,
		handler: HandlerFunc(func(_ context.Context, req *dns.Msg, _ net.Addr) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.40"),
			}}
			return resp, nil
		}),
	}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		listener.handleConnection(server)
		close(done)
	}()

	for id := uint16(1); id <= 2; id++ {
		query := new(dns.Msg)
		query.SetQuestion("pooled.example.", dns.TypeA)
		query.Id = id
		writeDNSFrameForTest(t, client, query)

		resp := readDNSFrameForTest(t, client)
		if resp.Id != id || len(resp.Answer) != 1 {
			t.Fatalf("response id=%d answers=%d, want id=%d and one answer", resp.Id, len(resp.Answer), id)
		}
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DoT connection handler did not stop")
	}
}

func writeDNSFrameForTest(t *testing.T, conn net.Conn, msg *dns.Msg) {
	t.Helper()
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	frame := make([]byte, len(wire)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)
	if err := writeFull(conn, frame); err != nil {
		t.Fatalf("writeFull: %v", err)
	}
}

func readDNSFrameForTest(t *testing.T, conn net.Conn) *dns.Msg {
	t.Helper()
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read header: %v", err)
	}
	wire := make([]byte, binary.BigEndian.Uint16(header[:]))
	if _, err := io.ReadFull(conn, wire); err != nil {
		t.Fatalf("read message: %v", err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return msg
}
