//go:build linux

package server

import (
	"encoding/base64"
	"net"
	"testing"
	"time"

	dnstsig "github.com/afterdarksys/dnsscienced/internal/tsig"
	"github.com/afterdarksys/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func TestLinuxUDPBatchListenerUsesProductionHandler(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.TCPAddr = ""
	cfg.UDPListeners = 1
	cfg.UDPBatchSize = 8
	cfg.EnableAuthoritative = true
	cfg.Zones = map[string]*zone.Zone{"example.com.": testZone()}
	cfg.TsigKeys = []dnstsig.KeyConfig{{
		Name:      "batch-test.",
		Algorithm: "hmac-sha256",
		Secret:    base64.StdEncoding.EncodeToString([]byte("correct-batch-test-secret")),
	}}

	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop() //nolint:errcheck

	address := srv.udpServers[0].PacketConn.LocalAddr().String()
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeSOA)
	response, _, err := client.Exchange(request, address)
	if err != nil {
		t.Fatal(err)
	}
	if response.Rcode != dns.RcodeSuccess || !response.Authoritative ||
		(len(response.Answer) == 0 && len(response.Ns) == 0) {
		t.Fatalf("response = %+v, want authoritative SOA answer", response)
	}
	badTSIG := new(dns.Msg)
	badTSIG.SetQuestion("example.com.", dns.TypeSOA)
	badTSIG.SetTsig("batch-test.", dns.HmacSHA256, 300, time.Now().Unix())
	wire, _, err := dns.TsigGenerate(
		badTSIG,
		base64.StdEncoding.EncodeToString([]byte("wrong-batch-test-secret")),
		"",
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", nil, srv.udpServers[0].PacketConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	badResponse := new(dns.Msg)
	if err := badResponse.Unpack(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	responseTSIG := badResponse.IsTsig()
	if badResponse.Rcode != dns.RcodeNotAuth ||
		responseTSIG == nil ||
		responseTSIG.Error != dns.RcodeBadSig ||
		responseTSIG.MACSize != 0 {
		t.Fatalf("bad-TSIG response = %+v TSIG=%+v, want unsigned NOTAUTH/BADSIG", badResponse, responseTSIG)
	}

	if got := srv.GetStats(); got.UDPQueries != 2 || got.TCPQueries != 0 {
		t.Fatalf("transport stats = %+v, want two UDP queries", got)
	} else if got.UDPBatchReadCalls == 0 || got.UDPBatchDatagrams != 2 {
		t.Fatalf("batch stats = %+v, want two received datagrams", got)
	}
	if _, ok := srv.udpServers[0].PacketConn.LocalAddr().(*net.UDPAddr); !ok {
		t.Fatalf("local address = %T, want UDP", srv.udpServers[0].PacketConn.LocalAddr())
	}
}
