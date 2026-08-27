package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/ede"
	"github.com/afterdarksys/dnsscienced/internal/transport"
	"github.com/afterdarksys/dnsscienced/internal/tsig"
	"github.com/afterdarksys/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

const (
	xotTestKeyName = "xot-transfer.example."
	xotTestSecret  = "c2VjcmV0"
)

func TestHandleXoTRejectsNonTransferTrafficWithEDE(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	writer := newAXFRTestWriter("192.0.2.100")
	writer.tlsState = &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		NegotiatedProtocol: "dot",
	}
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeSOA)

	s.handleXoT(writer, request)

	if len(writer.msgs) != 1 || writer.msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("responses = %+v, want one REFUSED", writer.msgs)
	}
	edes := ede.GetEDEFromMessage(&writer.msgs[0])
	if len(edes) != 1 || edes[0].InfoCode != ede.InfoCodeNotSupported {
		t.Fatalf("EDEs = %+v, want Not Supported", edes)
	}
}

func TestHandleXoTClosesConnectionWithoutRequiredALPN(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	writer := newAXFRTestWriter("192.0.2.100")
	writer.tlsState = &tls.ConnectionState{Version: tls.VersionTLS13}

	s.handleXoT(writer, makeAXFRRequest("example.com."))

	if !writer.closed || len(writer.msgs) != 0 {
		t.Fatalf("closed=%v responses=%v", writer.closed, writer.msgs)
	}
}

func TestHandleAXFRHonorsTLSOnlyPolicy(t *testing.T) {
	s, err := testServerWithAXFR([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	s.cfg.ZoneTransferTLSOnly = map[string]bool{"example.com.": true}
	request := makeAXFRRequest("example.com.")
	request.SetTsig(xotTestKeyName, dns.HmacSHA256, 300, time.Now().Unix())

	cleartext := newAXFRTestWriter("192.0.2.100")
	s.handleAXFR(cleartext, request, net.ParseIP("192.0.2.100"))
	if len(cleartext.msgs) != 1 || cleartext.msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("cleartext responses = %+v, want REFUSED", cleartext.msgs)
	}

	encrypted := newAXFRTestWriter("192.0.2.100")
	encrypted.tlsState = &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		NegotiatedProtocol: "dot",
	}
	s.handleAXFR(encrypted, request, net.ParseIP("192.0.2.100"))
	if len(encrypted.msgs) == 0 || encrypted.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("encrypted responses = %+v, want transfer", encrypted.msgs)
	}
}

func TestPrimaryStreamsAuthenticatedAXFROverMutualTLS(t *testing.T) {
	material := newXoTTestMaterial(t)
	cfg := Config{
		UDPAddr:       "127.0.0.1:0",
		TCPAddr:       "",
		UDPListeners:  1,
		TCPProtection: transport.DefaultTCPProtectionConfig(),
		Zones:         map[string]*zone.Zone{"example.com.": testZone()},
		TsigKeys: []tsig.KeyConfig{{
			Name:      xotTestKeyName,
			Algorithm: dns.HmacSHA256,
			Secret:    xotTestSecret,
		}},
		ZoneTransferCIDRs:   map[string][]string{"example.com.": {"127.0.0.0/8"}},
		ZoneTransferTLSOnly: map[string]bool{"example.com.": true},
		XoT: XoTConfig{
			Enabled:           true,
			Address:           "127.0.0.1:0",
			CertFile:          material.serverCertFile,
			KeyFile:           material.serverKeyFile,
			ClientCAFile:      material.caFile,
			RequireClientCert: true,
		},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck

	request := makeAXFRRequest("example.com.")
	request.SetTsig(xotTestKeyName, dns.HmacSHA256, 300, time.Now().Unix())
	transfer := &dns.Transfer{
		TLS: material.clientTLSConfig(t, true),
		TsigSecret: map[string]string{
			xotTestKeyName: xotTestSecret,
		},
	}
	envelopes, err := transfer.In(request, s.xotServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var records []dns.RR
	for envelope := range envelopes {
		if envelope.Error != nil {
			t.Fatal(envelope.Error)
		}
		records = append(records, envelope.RR...)
	}
	if len(records) < 2 {
		t.Fatalf("transfer returned %d records", len(records))
	}
	if accepted := s.GetStats().XoTConnections.Accepted; accepted == 0 {
		t.Fatal("XoT listener did not expose TCP admission statistics")
	}
	first, firstOK := records[0].(*dns.SOA)
	last, lastOK := records[len(records)-1].(*dns.SOA)
	if !firstOK || !lastOK || first.Serial != last.Serial {
		t.Fatalf("transfer is not bounded by matching SOAs: %v", records)
	}

	unsignedIdentityRequest := makeAXFRRequest("example.com.")
	unsignedIdentityRequest.SetTsig(xotTestKeyName, dns.HmacSHA256, 300, time.Now().Unix())
	withoutClientIdentity := &dns.Transfer{
		TLS: material.clientTLSConfig(t, false),
		TsigSecret: map[string]string{
			xotTestKeyName: xotTestSecret,
		},
	}
	envelopes, err = withoutClientIdentity.In(
		unsignedIdentityRequest,
		s.xotServer.Listener.Addr().String(),
	)
	if err == nil {
		for envelope := range envelopes {
			if envelope.Error != nil {
				err = envelope.Error
				break
			}
		}
	}
	if err == nil {
		t.Fatal("mTLS listener accepted a transfer without a client certificate")
	}
}

func TestLoadXoTTLSConfigRequiresCompleteMutualTLSConfig(t *testing.T) {
	material := newXoTTestMaterial(t)
	_, err := loadXoTTLSConfig(XoTConfig{
		CertFile:          material.serverCertFile,
		KeyFile:           material.serverKeyFile,
		RequireClientCert: true,
	})
	if err == nil {
		t.Fatal("required client certificate accepted without a client CA")
	}
}

func TestLoadXoTTLSConfigEnforcesRFC9103(t *testing.T) {
	material := newXoTTestMaterial(t)
	cfg, err := loadXoTTLSConfig(XoTConfig{
		CertFile:     material.serverCertFile,
		KeyFile:      material.serverKeyFile,
		ClientCAFile: material.caFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 ||
		len(cfg.NextProtos) != 1 ||
		cfg.NextProtos[0] != "dot" ||
		cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("TLS config = %#v", cfg)
	}
}

type xotTestMaterial struct {
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
}

func newXoTTestMaterial(t *testing.T) xotTestMaterial {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "XoT test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)

	issue := func(serial int64, name string, server bool) (string, string) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		dnsNames := []string(nil)
		if server {
			usage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			dnsNames = []string{"primary.test"}
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: name},
			DNSNames:     dnsNames,
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  usage,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certFile := filepath.Join(dir, name+"-cert.pem")
		keyFile := filepath.Join(dir, name+"-key.pem")
		writePEM(t, certFile, "CERTIFICATE", certDER)
		writePEM(t, keyFile, "PRIVATE KEY", keyDER)
		return certFile, keyFile
	}
	serverCert, serverKey := issue(2, "primary", true)
	clientCert, clientKey := issue(3, "secondary", false)
	return xotTestMaterial{
		caFile:         caFile,
		serverCertFile: serverCert,
		serverKeyFile:  serverKey,
		clientCertFile: clientCert,
		clientKeyFile:  clientKey,
	}
}

func (m xotTestMaterial) clientTLSConfig(t *testing.T, mutual bool) *tls.Config {
	t.Helper()
	caPEM, err := os.ReadFile(m.caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA did not parse")
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "primary.test",
		RootCAs:    roots,
		NextProtos: []string{"dot"},
	}
	if mutual {
		certificate, err := tls.LoadX509KeyPair(m.clientCertFile, m.clientKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{certificate}
	}
	return cfg
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
