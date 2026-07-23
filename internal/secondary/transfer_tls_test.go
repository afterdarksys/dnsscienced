package secondary

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAXFRFetcherTransfersOverStrictTLS(t *testing.T) {
	material := newTransferTLSMaterial(t)
	listener, shutdown := startTransferTLSServer(t, material.serverConfig(false), "dot")
	defer shutdown()

	transferred, err := (AXFRFetcher{Timeout: time.Second}).Fetch(
		context.Background(),
		Config{
			Name:        "secondary.test.",
			Masters:     []string{listener.Addr().String()},
			TransferTLS: material.clientConfig(false),
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.SOA == nil || transferred.SOA.Serial != 7 {
		t.Fatalf("transferred SOA = %v", transferred.SOA)
	}
}

func TestAXFRFetcherTransfersOverMutualTLS(t *testing.T) {
	material := newTransferTLSMaterial(t)
	listener, shutdown := startTransferTLSServer(t, material.serverConfig(true), "dot")
	defer shutdown()

	_, err := (AXFRFetcher{Timeout: time.Second}).Fetch(
		context.Background(),
		Config{
			Name:        "secondary.test.",
			Masters:     []string{listener.Addr().String()},
			TransferTLS: material.clientConfig(true),
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAXFRFetcherRejectsMissingMutualTLSIdentity(t *testing.T) {
	material := newTransferTLSMaterial(t)
	listener, shutdown := startTransferTLSServer(t, material.serverConfig(true), "dot")
	defer shutdown()

	_, err := (AXFRFetcher{Timeout: time.Second}).Fetch(
		context.Background(),
		Config{
			Name:        "secondary.test.",
			Masters:     []string{listener.Addr().String()},
			TransferTLS: material.clientConfig(false),
		},
		nil,
	)
	if err == nil {
		t.Fatal("transfer without required client certificate succeeded")
	}
}

func TestAXFRFetcherRequiresDoTALPN(t *testing.T) {
	material := newTransferTLSMaterial(t)
	listener, shutdown := startTransferTLSServer(t, material.serverConfig(false), "")
	defer shutdown()

	_, err := (AXFRFetcher{Timeout: time.Second}).Fetch(
		context.Background(),
		Config{
			Name:        "secondary.test.",
			Masters:     []string{listener.Addr().String()},
			TransferTLS: material.clientConfig(false),
		},
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "required ALPN") {
		t.Fatalf("error = %v, want required ALPN failure", err)
	}
}

func TestAXFRFetcherAuthenticatesPrimaryName(t *testing.T) {
	material := newTransferTLSMaterial(t)
	listener, shutdown := startTransferTLSServer(t, material.serverConfig(false), "dot")
	defer shutdown()
	clientTLS := material.clientConfig(false)
	clientTLS.ServerName = "impostor.test"

	_, err := (AXFRFetcher{Timeout: time.Second}).Fetch(
		context.Background(),
		Config{
			Name:        "secondary.test.",
			Masters:     []string{listener.Addr().String()},
			TransferTLS: clientTLS,
		},
		nil,
	)
	if err == nil {
		t.Fatal("transfer accepted a primary certificate for the wrong authentication name")
	}
}

func TestAXFRFetcherNeverFallsBackFromTLSToCleartext(t *testing.T) {
	material := newTransferTLSMaterial(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, shutdown := startTransferServer(t, listener)
	defer shutdown()

	_, err = (AXFRFetcher{Timeout: time.Second}).Fetch(
		context.Background(),
		Config{
			Name:        "secondary.test.",
			Masters:     []string{listener.Addr().String()},
			TransferTLS: material.clientConfig(false),
		},
		nil,
	)
	if err == nil {
		t.Fatal("TLS-configured transfer fell back to cleartext")
	}
}

func TestPrepareManagedZoneEnforcesStrictTransferTLS(t *testing.T) {
	tests := []struct {
		name      string
		tlsConfig *tls.Config
		want      string
	}{
		{
			name:      "server name required",
			tlsConfig: &tls.Config{MinVersion: tls.VersionTLS13},
			want:      "server_name is required",
		},
		{
			name: "verification cannot be disabled",
			tlsConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				ServerName:         "primary.test",
				InsecureSkipVerify: true, //nolint:gosec -- verifies fail-closed validation.
			},
			want: "cannot skip server verification",
		},
		{
			name: "TLS 1.2 rejected",
			tlsConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: "primary.test",
			},
			want: "minimum version must be TLS 1.3",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := prepareManagedZone(Config{
				Name:                  "secondary.test.",
				Masters:               []string{"192.0.2.1"},
				TransferTLS:           test.tlsConfig,
				AllowUnsignedTransfer: true,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPrepareManagedZoneDefaultsXoTPort(t *testing.T) {
	managed, err := prepareManagedZone(Config{
		Name:    "secondary.test.",
		Masters: []string{"192.0.2.1"},
		TransferTLS: &tls.Config{
			ServerName: "primary.test",
		},
		AllowUnsignedTransfer: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := managed.cfg.Masters[0]; got != "192.0.2.1:853" {
		t.Fatalf("master = %q, want RFC 9103 port 853", got)
	}
	if managed.cfg.TransferTLS.MinVersion != tls.VersionTLS13 ||
		len(managed.cfg.TransferTLS.NextProtos) != 1 ||
		managed.cfg.TransferTLS.NextProtos[0] != "dot" {
		t.Fatalf("normalized TLS config = %#v", managed.cfg.TransferTLS)
	}
}

type transferTLSMaterial struct {
	roots      *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

func newTransferTLSMaterial(t *testing.T) transferTLSMaterial {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "transfer test CA"},
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
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	issue := func(serial int64, commonName string, server bool) tls.Certificate {
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
			Subject:      pkix.Name{CommonName: commonName},
			DNSNames:     dnsNames,
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  usage,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	return transferTLSMaterial{
		roots:      roots,
		serverCert: issue(2, "primary.test", true),
		clientCert: issue(3, "secondary.test", false),
	}
}

func (m transferTLSMaterial) clientConfig(mutual bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "primary.test",
		RootCAs:    m.roots,
		NextProtos: []string{"dot"},
	}
	if mutual {
		cfg.Certificates = []tls.Certificate{m.clientCert}
	}
	return cfg
}

func (m transferTLSMaterial) serverConfig(mutual bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{m.serverCert},
		NextProtos:   []string{"dot"},
	}
	if mutual {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = m.roots
	}
	return cfg
}

func startTransferTLSServer(
	t *testing.T,
	tlsConfig *tls.Config,
	alpn string,
) (net.Listener, func()) {
	t.Helper()
	if alpn == "" {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.NextProtos = nil
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(raw, tlsConfig)
	_, shutdown := startTransferServer(t, listener)
	return raw, shutdown
}

func startTransferServer(t *testing.T, listener net.Listener) (*dns.Server, func()) {
	t.Helper()
	source := validZone("secondary.test.", 7)
	records := []dns.RR{source.SOA}
	for _, rr := range source.GetAllRecords() {
		if rr.Header().Rrtype != dns.TypeSOA {
			records = append(records, rr)
		}
	}
	records = append(records, source.SOA)
	server := &dns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
			envelopes := make(chan *dns.Envelope, 1)
			envelopes <- &dns.Envelope{RR: records}
			close(envelopes)
			_ = new(dns.Transfer).Out(w, request, envelopes)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	return server, func() {
		_ = server.Shutdown()
		<-done
	}
}
