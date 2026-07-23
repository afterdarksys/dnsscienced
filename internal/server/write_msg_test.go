package server

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

type countingResponseWriter struct {
	rawWrites int
	msgWrites int
}

func (w *countingResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (w *countingResponseWriter) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (w *countingResponseWriter) Close() error         { return nil }
func (w *countingResponseWriter) TsigStatus() error    { return nil }
func (w *countingResponseWriter) TsigTimersOnly(bool)  {}
func (w *countingResponseWriter) Hijack()              {}
func (w *countingResponseWriter) Write(p []byte) (int, error) {
	w.rawWrites++
	return len(p), nil
}
func (w *countingResponseWriter) WriteMsg(*dns.Msg) error {
	w.msgWrites++
	return nil
}

func TestWriteMsgUsesPooledWirePathForUnsignedResponses(t *testing.T) {
	writer := new(countingResponseWriter)
	msg := new(dns.Msg)
	msg.SetQuestion("example.", dns.TypeA)
	msg.Response = true

	if err := writeMsg(writer, msg); err != nil {
		t.Fatalf("writeMsg: %v", err)
	}
	if writer.rawWrites != 1 || writer.msgWrites != 0 {
		t.Fatalf("raw writes=%d message writes=%d, want 1 and 0", writer.rawWrites, writer.msgWrites)
	}
}

func TestWriteMsgPreservesTSIGWriterPath(t *testing.T) {
	writer := new(countingResponseWriter)
	msg := new(dns.Msg)
	msg.SetQuestion("example.", dns.TypeA)
	msg.SetTsig("key.example.", dns.HmacSHA256, 300, 1)

	if err := writeMsg(writer, msg); err != nil {
		t.Fatalf("writeMsg: %v", err)
	}
	if writer.rawWrites != 0 || writer.msgWrites != 1 {
		t.Fatalf("raw writes=%d message writes=%d, want 0 and 1", writer.rawWrites, writer.msgWrites)
	}
}

var benchmarkWire []byte

func BenchmarkResponsePacking(b *testing.B) {
	msg := new(dns.Msg)
	msg.SetQuestion("www.example.", dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.41"),
	}}

	b.Run("Pack", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			benchmarkWire, _ = msg.Pack()
		}
	})

	writer := new(countingResponseWriter)
	b.Run("PooledWrite", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_ = writeMsg(writer, msg)
		}
	})
}
