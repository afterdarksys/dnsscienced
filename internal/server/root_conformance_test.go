package server

import (
	"net"
	"testing"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func signedRootTestZone(t *testing.T) *zone.Zone {
	t.Helper()
	z := zone.New(".")
	records := []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 86400},
			Ns:  "a.root.test.", Mbox: "hostmaster.root.test.", Serial: 2026072301,
			Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 86400,
		},
		&dns.NS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86400},
			Ns:  "a.root.test.",
		},
		&dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 86400},
			Flags:     257,
			Protocol:  3,
			Algorithm: dns.RSASHA256,
			PublicKey: "AwEAAQ==",
		},
		testRootSignature(".", dns.TypeSOA),
		testRootSignature(".", dns.TypeNS),
		testRootSignature(".", dns.TypeDNSKEY),
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400},
			NextDomain: "com.",
			TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
		},
		testRootSignature(".", dns.TypeNSEC),
		&dns.NS{
			Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
			Ns:  "ns.com.",
		},
		&dns.DS{
			Hdr:        dns.RR_Header{Name: "com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 86400},
			KeyTag:     12345,
			Algorithm:  dns.RSASHA256,
			DigestType: dns.SHA256,
			Digest:     "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		},
		testRootSignature("com.", dns.TypeDS),
		&dns.NSEC{
			Hdr:        dns.RR_Header{Name: "com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400},
			NextDomain: ".",
			TypeBitMap: []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC},
		},
		testRootSignature("com.", dns.TypeNSEC),
		&dns.A{
			Hdr: dns.RR_Header{Name: "a.root.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 86400},
			A:   net.ParseIP("192.0.2.53"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "a.root.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 86400},
			AAAA: net.ParseIP("2001:db8::53"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 172800},
			A:   net.ParseIP("192.0.2.80"),
		},
	}
	for _, rr := range records {
		if err := z.AddRecord(rr); err != nil {
			t.Fatalf("AddRecord(%s): %v", rr, err)
		}
	}
	return z
}

func testRootSignature(owner string, covered uint16) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 86400},
		TypeCovered: covered,
		Algorithm:   dns.RSASHA256,
		Labels:      uint8(len(dns.SplitDomainName(owner))),
		OrigTtl:     86400,
		Expiration:  4_102_444_800,
		Inception:   1_700_000_000,
		KeyTag:      12345,
		SignerName:  ".",
		Signature:   "AA==",
	}
}

func TestRootRoleRejectsUnsignedOrIncompleteZone(t *testing.T) {
	unsigned := zone.New(".")
	if err := unsigned.AddRecord(&dns.SOA{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET},
		Ns:  "a.root.test.", Mbox: "hostmaster.root.test.",
	}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Zones: map[string]*zone.Zone{".": unsigned}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop() //nolint:errcheck
	if err := srv.ValidateRootAuthoritativeZone(); err == nil {
		t.Fatal("unsigned root zone passed runtime conformance validation")
	}

	signed := signedRootTestZone(t)
	srv, err = New(Config{Zones: map[string]*zone.Zone{".": signed}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop() //nolint:errcheck
	if err := srv.ValidateRootAuthoritativeZone(); err != nil {
		t.Fatalf("signed root validation: %v", err)
	}

	for _, rr := range signed.ExactRecords(".", dns.TypeRRSIG) {
		if signature, ok := rr.(*dns.RRSIG); ok && signature.TypeCovered == dns.TypeSOA {
			signature.Expiration = 1
		}
	}
	if err := srv.ValidateRootAuthoritativeZone(); err == nil {
		t.Fatal("root zone with an expired apex signature passed validation")
	}
}

func TestRootAuthoritativeDNSSECAndEDNSConformance(t *testing.T) {
	srv, err := New(Config{
		EnableAuthoritative: true,
		Zones:               map[string]*zone.Zone{".": signedRootTestZone(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop() //nolint:errcheck

	dnskey := rootQuery(t, srv, ".", dns.TypeDNSKEY, true)
	if !dnskey.Authoritative || dnskey.RecursionAvailable ||
		!hasRRType(dnskey.Answer, dns.TypeDNSKEY) ||
		!hasCoveredSignature(dnskey.Answer, dns.TypeDNSKEY) ||
		dnskey.IsEdns0() == nil {
		t.Fatalf("DNSKEY response is not authoritative DNSSEC+EDNS: %+v", dnskey)
	}

	referral := rootQuery(t, srv, "www.com.", dns.TypeA, true)
	if referral.Authoritative || !hasRRType(referral.Ns, dns.TypeNS) ||
		!hasRRType(referral.Ns, dns.TypeDS) ||
		!hasCoveredSignature(referral.Ns, dns.TypeDS) {
		t.Fatalf("signed referral = %+v", referral)
	}

	nxdomain := rootQuery(t, srv, "missing.", dns.TypeA, true)
	if nxdomain.Rcode != dns.RcodeNameError || !nxdomain.Authoritative ||
		!hasRRType(nxdomain.Ns, dns.TypeSOA) ||
		!hasCoveredSignature(nxdomain.Ns, dns.TypeSOA) ||
		!hasRRType(nxdomain.Ns, dns.TypeNSEC) ||
		!hasCoveredSignature(nxdomain.Ns, dns.TypeNSEC) {
		t.Fatalf("signed NXDOMAIN = %+v", nxdomain)
	}

	nodata := rootQuery(t, srv, ".", dns.TypeTXT, true)
	if nodata.Rcode != dns.RcodeSuccess || len(nodata.Answer) != 0 ||
		!hasRRType(nodata.Ns, dns.TypeSOA) ||
		!hasRRType(nodata.Ns, dns.TypeNSEC) ||
		!hasCoveredSignature(nodata.Ns, dns.TypeNSEC) {
		t.Fatalf("signed NODATA = %+v", nodata)
	}
}

func TestRootAuthoritativeSupportsIPv4IPv6UDPAndTCP(t *testing.T) {
	for _, family := range []struct {
		name    string
		network string
		address string
	}{
		{name: "IPv4", network: "4", address: "127.0.0.1:0"},
		{name: "IPv6", network: "6", address: "[::1]:0"},
	} {
		t.Run(family.name, func(t *testing.T) {
			packetConn, err := net.ListenPacket("udp"+family.network, family.address)
			if err != nil {
				t.Fatalf("bind UDP %s: %v", family.name, err)
			}
			cfg := DefaultConfig()
			cfg.UDPAddr = family.address
			cfg.TCPAddr = family.address
			cfg.UDPListeners = 1
			cfg.EnableAuthoritative = true
			cfg.Zones = map[string]*zone.Zone{".": signedRootTestZone(t)}
			srv, err := New(cfg)
			if err != nil {
				_ = packetConn.Close()
				t.Fatal(err)
			}
			srv.udpServers[0].PacketConn = packetConn
			if err := srv.Start(); err != nil {
				_ = packetConn.Close()
				t.Fatal(err)
			}
			defer srv.Stop() //nolint:errcheck

			for _, transport := range []struct {
				network string
				address string
			}{
				{network: "udp" + family.network, address: packetConn.LocalAddr().String()},
				{network: "tcp" + family.network, address: srv.tcpServer.Listener.Addr().String()},
			} {
				request := new(dns.Msg)
				request.SetQuestion(".", dns.TypeSOA)
				client := &dns.Client{Net: transport.network, Timeout: 2 * time.Second}
				response, _, err := client.Exchange(request, transport.address)
				if err != nil {
					t.Fatalf("%s exchange: %v", transport.network, err)
				}
				if !response.Authoritative || response.RecursionAvailable ||
					!hasRRType(response.Answer, dns.TypeSOA) {
					t.Fatalf("%s response = %+v", transport.network, response)
				}
			}
		})
	}
}

func rootQuery(t *testing.T, srv *Server, name string, rrtype uint16, do bool) *dns.Msg {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion(name, rrtype)
	request.SetEdns0(1232, do)
	writer := newTestResponseWriter("198.51.100.10")
	srv.handleDNS(writer, request)
	if writer.msg == nil {
		t.Fatal("root query produced no response")
	}
	return writer.msg
}

func hasRRType(records []dns.RR, rrtype uint16) bool {
	for _, rr := range records {
		if rr.Header().Rrtype == rrtype {
			return true
		}
	}
	return false
}

func hasCoveredSignature(records []dns.RR, covered uint16) bool {
	for _, rr := range records {
		signature, ok := rr.(*dns.RRSIG)
		if ok && signature.TypeCovered == covered {
			return true
		}
	}
	return false
}
