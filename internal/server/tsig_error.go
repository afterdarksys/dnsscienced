package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	dnstsig "github.com/dnsscience/dnsscienced/internal/tsig"
	"github.com/miekg/dns"
)

type tsigSigningResponseWriter struct {
	dns.ResponseWriter
	keyName   string
	algorithm string
	fudge     uint16
}

func newTSIGSigningResponseWriter(w dns.ResponseWriter, requestTSIG *dns.TSIG) dns.ResponseWriter {
	if w == nil || requestTSIG == nil {
		return w
	}
	return &tsigSigningResponseWriter{
		ResponseWriter: w,
		keyName:        requestTSIG.Hdr.Name,
		algorithm:      requestTSIG.Algorithm,
		fudge:          requestTSIG.Fudge,
	}
}

func (w *tsigSigningResponseWriter) WriteMsg(message *dns.Msg) error {
	if message.IsTsig() != nil {
		return w.ResponseWriter.WriteMsg(message)
	}
	signed := message.Copy()
	signed.SetTsig(w.keyName, w.algorithm, w.fudge, time.Now().Unix())
	return w.ResponseWriter.WriteMsg(signed)
}

func (w *tsigSigningResponseWriter) Write(wire []byte) (int, error) {
	message := new(dns.Msg)
	if err := message.Unpack(wire); err != nil {
		return 0, err
	}
	if err := w.WriteMsg(message); err != nil {
		return 0, err
	}
	return len(wire), nil
}

func (w *tsigSigningResponseWriter) ConnectionState() *tls.ConnectionState {
	if provider, ok := w.ResponseWriter.(dns.ConnectionStater); ok {
		return provider.ConnectionState()
	}
	return nil
}

// writeTSIGVerificationError emits the RFC 8945 extended error appropriate to
// a parsed TSIG request that failed authentication. BADKEY and BADSIG are
// deliberately unsigned; miekg/dns preserves their empty MACs when Error is
// set. BADTIME and BADTRUNC are signed because the request MAC was validated.
func writeTSIGVerificationError(w dns.ResponseWriter, request *dns.Msg, verificationErr error) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Rcode = dns.RcodeNotAuth

	requestTSIG := request.IsTsig()
	if requestTSIG == nil {
		w.WriteMsg(response) //nolint:errcheck
		return
	}

	if errors.Is(verificationErr, dnstsig.ErrMalformedMAC) {
		response.Rcode = dns.RcodeFormatError
		w.WriteMsg(response) //nolint:errcheck
		return
	}

	now := time.Now().Unix()
	timeSigned := now
	tsigError := uint16(dns.RcodeBadSig)
	switch {
	case errors.Is(verificationErr, dns.ErrSecret),
		errors.Is(verificationErr, dns.ErrKey),
		errors.Is(verificationErr, dns.ErrKeyAlg):
		tsigError = dns.RcodeBadKey
	case errors.Is(verificationErr, dns.ErrTime):
		tsigError = dns.RcodeBadTime
		timeSigned = int64(requestTSIG.TimeSigned)
	case errors.Is(verificationErr, dnstsig.ErrBadTruncation):
		tsigError = dns.RcodeBadTrunc
	}

	response.SetTsig(requestTSIG.Hdr.Name, requestTSIG.Algorithm, requestTSIG.Fudge, timeSigned)
	responseTSIG := response.IsTsig()
	responseTSIG.Error = tsigError
	if tsigError == dns.RcodeBadTime {
		responseTSIG.OtherLen = 6
		responseTSIG.OtherData = fmt.Sprintf("%012x", now)
	}
	w.WriteMsg(response) //nolint:errcheck
}
