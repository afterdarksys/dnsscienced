//go:build linux

package transport

import (
	"net"
	"testing"
	"time"
)

func TestUDPBatchPacketConnRoundTripPreservesUDPAddress(t *testing.T) {
	server, err := ListenUDPReusePort("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := NewUDPBatchPacketConn(server, 8, 512)
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	defer packetConn.Close()

	client, err := net.DialUDP("udp4", nil, packetConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 512)
	n, source, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	udpSource, ok := UDPAddress(source)
	if !ok || !udpSource.IP.IsLoopback() {
		t.Fatalf("source = %T %v, want loopback UDP", source, source)
	}
	if string(buffer[:n]) != "request" {
		t.Fatalf("payload = %q", buffer[:n])
	}
	if _, err := packetConn.WriteTo([]byte("response"), source); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "response" {
		t.Fatalf("response = %q", buffer[:n])
	}
}
