package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	dnstsig "github.com/afterdarksys/dnsscienced/internal/tsig"
	"github.com/miekg/dns"
)

func tsigErrorRequest() *dns.Msg {
	request := new(dns.Msg)
	request.SetUpdate("example.com.")
	request.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Add(-10*time.Minute).Unix())
	request.IsTsig().MAC = "aabbccdd"
	request.IsTsig().MACSize = 4
	return request
}

func TestWriteTSIGVerificationErrorClassifiesRFC8945Errors(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		rcode     int
		tsigError uint16
		hasTSIG   bool
	}{
		{name: "bad signature", err: dns.ErrSig, rcode: dns.RcodeNotAuth, tsigError: dns.RcodeBadSig, hasTSIG: true},
		{name: "unknown key", err: dns.ErrSecret, rcode: dns.RcodeNotAuth, tsigError: dns.RcodeBadKey, hasTSIG: true},
		{name: "bad algorithm", err: dns.ErrKeyAlg, rcode: dns.RcodeNotAuth, tsigError: dns.RcodeBadKey, hasTSIG: true},
		{name: "bad time", err: dns.ErrTime, rcode: dns.RcodeNotAuth, tsigError: dns.RcodeBadTime, hasTSIG: true},
		{name: "bad truncation", err: dnstsig.ErrBadTruncation, rcode: dns.RcodeNotAuth, tsigError: dns.RcodeBadTrunc, hasTSIG: true},
		{name: "oversized MAC", err: dnstsig.ErrMalformedMAC, rcode: dns.RcodeFormatError, hasTSIG: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writer := newAXFRTestWriter("192.0.2.1")
			request := tsigErrorRequest()
			writeTSIGVerificationError(writer, request, tc.err)
			if len(writer.msgs) != 1 {
				t.Fatalf("responses = %d, want 1", len(writer.msgs))
			}
			response := &writer.msgs[0]
			if response.Rcode != tc.rcode {
				t.Fatalf("rcode = %d, want %d", response.Rcode, tc.rcode)
			}
			responseTSIG := response.IsTsig()
			if !tc.hasTSIG {
				if responseTSIG != nil {
					t.Fatalf("unexpected TSIG: %+v", responseTSIG)
				}
				return
			}
			if responseTSIG == nil || responseTSIG.Error != tc.tsigError {
				t.Fatalf("TSIG = %+v, want error %d", responseTSIG, tc.tsigError)
			}
			if tc.tsigError == dns.RcodeBadSig || tc.tsigError == dns.RcodeBadKey {
				if responseTSIG.MACSize != 0 || responseTSIG.MAC != "" {
					t.Fatalf("BADKEY/BADSIG response was signed: %+v", responseTSIG)
				}
			}
			if tc.tsigError == dns.RcodeBadTime {
				if responseTSIG.TimeSigned != request.IsTsig().TimeSigned ||
					responseTSIG.OtherLen != 6 ||
					len(responseTSIG.OtherData) != 12 {
					t.Fatalf("BADTIME response fields = %+v", responseTSIG)
				}
			}
		})
	}
}

func TestHandleDNSRejectsInvalidTSIGBeforeOpcodeDispatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPListeners = 1
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop() //nolint:errcheck

	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	request.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())
	writer := newAXFRTestWriter("192.0.2.1")
	writer.remoteAddr = &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53000}
	writer.tsigStatus = fmt.Errorf("invalid MAC: %w", dns.ErrSig)

	srv.handleDNS(writer, request)
	if len(writer.msgs) != 1 ||
		writer.msgs[0].Rcode != dns.RcodeNotAuth ||
		writer.msgs[0].IsTsig() == nil ||
		writer.msgs[0].IsTsig().Error != dns.RcodeBadSig {
		t.Fatalf("response = %+v, want NOTAUTH/BADSIG", writer.msgs)
	}
}

func TestHandleDNSSignsResponseToAuthenticatedQuery(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPListeners = 1
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop() //nolint:errcheck

	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	request.SetTsig("test.", dns.HmacSHA256, 300, time.Now().Unix())
	writer := newAXFRTestWriter("192.0.2.1")
	writer.remoteAddr = &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53000}

	srv.handleDNS(writer, request)
	if len(writer.msgs) != 1 {
		t.Fatalf("responses = %d, want 1", len(writer.msgs))
	}
	responseTSIG := writer.msgs[0].IsTsig()
	if responseTSIG == nil ||
		responseTSIG.Hdr.Name != request.IsTsig().Hdr.Name ||
		responseTSIG.Algorithm != request.IsTsig().Algorithm {
		t.Fatalf("response TSIG = %+v, want request key and algorithm", responseTSIG)
	}
}

func TestWriteTSIGVerificationErrorRecognizesWrappedErrors(t *testing.T) {
	writer := newAXFRTestWriter("192.0.2.1")
	writeTSIGVerificationError(writer, tsigErrorRequest(), fmt.Errorf("verify: %w", dns.ErrTime))
	if len(writer.msgs) != 1 {
		t.Fatal("wrapped BADTIME was not handled")
	}
	if got := writer.msgs[0].IsTsig(); got == nil || got.Error != dns.RcodeBadTime {
		t.Fatalf("TSIG = %+v, want BADTIME", got)
	}
}
