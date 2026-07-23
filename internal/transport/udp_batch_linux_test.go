//go:build linux

package transport

import (
	"bytes"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func listenUDP4(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestUDPBatchReadWrite(t *testing.T) {
	server := listenUDP4(t)
	client := listenUDP4(t)
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	batch, err := NewUDPBatchConn(server, 8, 512)
	if err != nil {
		t.Fatalf("NewUDPBatchConn: %v", err)
	}

	want := make(map[string]struct{}, 8)
	for i := 0; i < 8; i++ {
		payload := []byte(fmt.Sprintf("dns-packet-%d", i))
		want[string(payload)] = struct{}{}
		if _, err := client.WriteToUDP(payload, server.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("WriteToUDP: %v", err)
		}
	}

	var received []UDPDatagram
	for len(received) < len(want) {
		datagrams, err := batch.ReadBatch()
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		for _, datagram := range datagrams {
			if datagram.Truncated {
				t.Fatal("unexpected truncated datagram")
			}
			if _, ok := want[string(datagram.Payload)]; !ok {
				t.Fatalf("unexpected payload %q", datagram.Payload)
			}
			received = append(received, UDPDatagram{
				Payload: append([]byte("response:"), datagram.Payload...),
				Addr:    datagram.Addr,
			})
		}
	}

	for len(received) > 0 {
		n, err := batch.WriteBatch(received)
		if err != nil {
			t.Fatalf("WriteBatch: %v", err)
		}
		received = received[n:]
	}

	got := make(map[string]struct{}, len(want))
	buffer := make([]byte, 512)
	for range want {
		n, _, err := client.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("ReadFromUDP: %v", err)
		}
		got[string(buffer[:n])] = struct{}{}
	}
	for payload := range want {
		if _, ok := got["response:"+payload]; !ok {
			t.Fatalf("missing response for %q", payload)
		}
	}
}

func TestUDPBatchTruncation(t *testing.T) {
	server := listenUDP4(t)
	client := listenUDP4(t)
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))

	batch, err := NewUDPBatchConn(server, 1, 12)
	if err != nil {
		t.Fatalf("NewUDPBatchConn: %v", err)
	}
	payload := bytes.Repeat([]byte{0xab}, 64)
	if _, err := client.WriteToUDP(payload, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	datagrams, err := batch.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if len(datagrams) != 1 || !datagrams[0].Truncated || len(datagrams[0].Payload) != 12 {
		t.Fatalf("unexpected truncated batch: %+v", datagrams)
	}
}

func TestUDPBatchIPv6(t *testing.T) {
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer client.Close()
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	batch, err := NewUDPBatchConn(server, 4, 512)
	if err != nil {
		t.Fatalf("NewUDPBatchConn: %v", err)
	}
	if _, err := client.WriteToUDP([]byte("ipv6-query"), server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	datagrams, err := batch.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if len(datagrams) != 1 || string(datagrams[0].Payload) != "ipv6-query" {
		t.Fatalf("unexpected IPv6 batch: %+v", datagrams)
	}
	datagrams[0].Payload = []byte("ipv6-response")
	if n, err := batch.WriteBatch(datagrams); err != nil || n != 1 {
		t.Fatalf("WriteBatch = %d, %v", n, err)
	}
	buffer := make([]byte, 512)
	n, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	if string(buffer[:n]) != "ipv6-response" {
		t.Fatalf("unexpected IPv6 response %q", buffer[:n])
	}
}

func TestUDPBatchValidation(t *testing.T) {
	if _, err := NewUDPBatchConn(nil, 1, 512); err == nil {
		t.Fatal("nil connection unexpectedly accepted")
	}

	server := listenUDP4(t)
	if _, err := NewUDPBatchConn(server, -1, 512); err == nil {
		t.Fatal("negative batch size unexpectedly accepted")
	}
	if _, err := NewUDPBatchConn(server, maxUDPBatchSize+1, 512); err == nil {
		t.Fatal("oversized batch unexpectedly accepted")
	}
	if _, err := NewUDPBatchConn(server, 1, maxUDPDatagramSize+1); err == nil {
		t.Fatal("oversized packet slot unexpectedly accepted")
	}
	batch, err := NewUDPBatchConn(server, 1, 512)
	if err != nil {
		t.Fatalf("NewUDPBatchConn: %v", err)
	}
	if _, err := batch.WriteBatch([]UDPDatagram{{Payload: []byte("a")}, {Payload: []byte("b")}}); err == nil {
		t.Fatal("oversized batch unexpectedly accepted")
	}
	if _, err := batch.WriteBatch([]UDPDatagram{{Addr: server.LocalAddr().(*net.UDPAddr)}}); err == nil {
		t.Fatal("empty datagram unexpectedly accepted")
	}
	if _, err := batch.WriteBatch([]UDPDatagram{{Payload: []byte("a")}}); err == nil {
		t.Fatal("nil destination unexpectedly accepted")
	}
}

func BenchmarkUDPReceiveSyscalls(b *testing.B) {
	payload := bytes.Repeat([]byte{0x42}, 64)

	b.Run("ReadFromUDP", func(b *testing.B) {
		server := listenUDP4(b)
		client := listenUDP4(b)
		_ = server.SetReadBuffer(16 << 20)
		stop := floodUDP(client, server.LocalAddr().(*net.UDPAddr), payload)
		defer stop()

		buffer := make([]byte, 512)
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := server.ReadFromUDP(buffer); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(1, "datagrams/op")
	})

	b.Run("ReadBatch64", func(b *testing.B) {
		server := listenUDP4(b)
		client := listenUDP4(b)
		_ = server.SetReadBuffer(16 << 20)
		batch, err := NewUDPBatchConn(server, 64, 512)
		if err != nil {
			b.Fatal(err)
		}
		stop := floodUDP(client, server.LocalAddr().(*net.UDPAddr), payload)
		defer stop()

		var packets int64
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			datagrams, err := batch.ReadBatch()
			if err != nil {
				b.Fatal(err)
			}
			packets += int64(len(datagrams))
		}
		b.SetBytes(packets * int64(len(payload)) / int64(b.N))
		b.ReportMetric(float64(packets)/float64(b.N), "datagrams/op")
	})
}

func BenchmarkUDPSendSyscalls(b *testing.B) {
	payload := bytes.Repeat([]byte{0x24}, 64)

	b.Run("WriteToUDP64", func(b *testing.B) {
		server := listenUDP4(b)
		client := listenUDP4(b)
		stop := drainUDP(client)
		defer stop()
		destination := client.LocalAddr().(*net.UDPAddr)

		b.SetBytes(int64(64 * len(payload)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 0; j < 64; j++ {
				if _, err := server.WriteToUDP(payload, destination); err != nil {
					b.Fatal(err)
				}
			}
		}
		b.ReportMetric(64, "datagrams/op")
	})

	b.Run("WriteBatch64", func(b *testing.B) {
		server := listenUDP4(b)
		client := listenUDP4(b)
		stop := drainUDP(client)
		defer stop()
		batch, err := NewUDPBatchConn(server, 64, 512)
		if err != nil {
			b.Fatal(err)
		}
		destination := client.LocalAddr().(*net.UDPAddr)
		datagrams := make([]UDPDatagram, 64)
		for i := range datagrams {
			datagrams[i] = UDPDatagram{Payload: payload, Addr: destination}
		}

		b.SetBytes(int64(64 * len(payload)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			remaining := datagrams
			for len(remaining) > 0 {
				n, err := batch.WriteBatch(remaining)
				if err != nil {
					b.Fatal(err)
				}
				remaining = remaining[n:]
			}
		}
		b.ReportMetric(64, "datagrams/op")
	})
}

func floodUDP(conn *net.UDPConn, destination *net.UDPAddr, payload []byte) func() {
	var stopped atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stopped.Load() {
			for i := 0; i < 64; i++ {
				if _, err := conn.WriteToUDP(payload, destination); err != nil {
					return
				}
			}
		}
	}()
	return func() {
		stopped.Store(true)
		_ = conn.Close()
		<-done
	}
}

func drainUDP(conn *net.UDPConn) func() {
	var stopped atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 512)
		for !stopped.Load() {
			if _, _, err := conn.ReadFromUDP(buffer); err != nil {
				return
			}
		}
	}()
	return func() {
		stopped.Store(true)
		_ = conn.Close()
		<-done
	}
}
