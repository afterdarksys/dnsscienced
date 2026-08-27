package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/dnsscienced/internal/ede"
	"github.com/miekg/dns"
)

// XoTConfig configures the dedicated RFC 9103 zone-transfer-over-TLS
// listener. XoT remains separate from general DoT because AXFR and IXFR stream
// multiple DNS messages and require dns.ResponseWriter transfer semantics.
type XoTConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Address           string `yaml:"address"`
	CertFile          string `yaml:"cert_file"`
	KeyFile           string `yaml:"key_file"`
	ClientCAFile      string `yaml:"client_ca_file,omitempty"`
	RequireClientCert bool   `yaml:"require_client_cert,omitempty"`
}

func xotAddress(cfg XoTConfig) string {
	if address := strings.TrimSpace(cfg.Address); address != "" {
		return address
	}
	return ":853"
}

func loadXoTTLSConfig(cfg XoTConfig) (*tls.Config, error) {
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("cert_file and key_file must be configured together")
	}
	if cfg.CertFile == "" {
		return nil, fmt.Errorf("cert_file and key_file are required")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"dot"},
	}
	if cfg.ClientCAFile != "" {
		caPEM, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA file: %w", err)
		}
		clientCAs := x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("client CA file contains no certificates")
		}
		tlsConfig.ClientCAs = clientCAs
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}
	if cfg.RequireClientCert {
		if tlsConfig.ClientCAs == nil {
			return nil, fmt.Errorf("client_ca_file is required when require_client_cert is true")
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConfig, nil
}

func (s *Server) handleXoT(w dns.ResponseWriter, request *dns.Msg) {
	stateProvider, ok := w.(dns.ConnectionStater)
	if !ok {
		_ = w.Close()
		return
	}
	state := stateProvider.ConnectionState()
	if state == nil ||
		state.Version < tls.VersionTLS13 ||
		state.NegotiatedProtocol != "dot" {
		_ = w.Close()
		return
	}
	if request == nil ||
		request.Opcode != dns.OpcodeQuery ||
		len(request.Question) != 1 ||
		(request.Question[0].Qtype != dns.TypeAXFR &&
			request.Question[0].Qtype != dns.TypeIXFR) {
		response := new(dns.Msg)
		if request != nil {
			response.SetReply(request)
		}
		response.Rcode = dns.RcodeRefused
		ede.NewEDE(ede.InfoCodeNotSupported, "Not Supported").AddToMessage(response)
		_ = w.WriteMsg(response)
		return
	}
	s.handleDNS(w, request)
}

func isXoTWriter(w dns.ResponseWriter) bool {
	stateProvider, ok := w.(dns.ConnectionStater)
	if !ok {
		return false
	}
	state := stateProvider.ConnectionState()
	return state != nil &&
		state.Version >= tls.VersionTLS13 &&
		state.NegotiatedProtocol == "dot"
}
