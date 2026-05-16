// Package dsync implements RFC 9859 DSYNC (Generalized DNS Notifications).
// It provides the DSYNC RR type codec and a per-source-IP rate limiter for
// inbound NOTIFY messages.
package dsync

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/miekg/dns"
)

// TypeDSYNC is the DNS RR type number for DSYNC (RFC 9859).
// miekg/dns v1.1.72 does not define this type; we define it here.
const TypeDSYNC uint16 = 66

// Scheme values for DSYNC records (RFC 9859 §2).
const (
	// DSYNCSchemeNull is the null scheme (receivers MUST ignore records with Scheme=0).
	DSYNCSchemeNull uint8 = 0
	// DSYNCSchemeNOTIFY is the NOTIFY scheme (RFC 1996 NOTIFY).
	DSYNCSchemeNOTIFY uint8 = 1
)

// DSYNCRecord is the structured representation of a DSYNC RDATA.
//
// Wire format (RFC 9859 §2):
//
//	[RRtype: 2 bytes big-endian][Scheme: 1 byte][Port: 2 bytes big-endian][Target: wire-format domain name]
//
// Minimum RDATA length: 5 bytes (header) + 1 byte (root label) = 6 bytes.
type DSYNCRecord struct {
	// RRtype is which delegation record type triggers this endpoint.
	// Common values: dns.TypeCDS (59) or dns.TypeCSYNC (62).
	RRtype uint16
	// Scheme is the contact method. Value 1 = NOTIFY (RFC 1996).
	// Value 0 = null (receivers MUST ignore). Values 128-255 = private use.
	Scheme uint8
	// Port is the destination port for NOTIFY. Standard DNS port is 53.
	Port uint16
	// Target is the FQDN of the notification endpoint.
	Target string
}

// EncodeDSYNC encodes a DSYNCRecord to a hex string suitable for use as
// dns.RFC3597.Rdata. The wire format is defined in RFC 9859 §2.
func EncodeDSYNC(rec DSYNCRecord) (string, error) {
	// Build the fixed 5-byte header: [RRtype 2b][Scheme 1b][Port 2b]
	hdr := make([]byte, 5)
	binary.BigEndian.PutUint16(hdr[0:2], rec.RRtype)
	hdr[2] = rec.Scheme
	binary.BigEndian.PutUint16(hdr[3:5], rec.Port)

	// Encode the Target as a wire-format domain name (no compression).
	nameBuf := make([]byte, 255)
	n, err := dns.PackDomainName(dns.Fqdn(rec.Target), nameBuf, 0, nil, false)
	if err != nil {
		return "", fmt.Errorf("dsync encode target %q: %w", rec.Target, err)
	}

	// Append the packed domain name bytes to the header.
	buf := append(hdr, nameBuf[:n]...)
	return hex.EncodeToString(buf), nil
}

// DecodeDSYNC parses a hex-encoded DSYNC RDATA string into a DSYNCRecord.
// Returns an error if rdata is too short (< 6 bytes) or malformed.
//
// Security: performs length check before any field access to prevent panic
// on malformed inbound wire data (T-08-01).
func DecodeDSYNC(rdata string) (DSYNCRecord, error) {
	raw, err := hex.DecodeString(rdata)
	if err != nil {
		return DSYNCRecord{}, fmt.Errorf("dsync hex decode: %w", err)
	}
	if len(raw) < 6 {
		return DSYNCRecord{}, fmt.Errorf("dsync rdata too short: %d bytes", len(raw))
	}

	rec := DSYNCRecord{
		RRtype: binary.BigEndian.Uint16(raw[0:2]),
		Scheme: raw[2],
		Port:   binary.BigEndian.Uint16(raw[3:5]),
	}

	// Unpack the wire-format domain name starting at offset 5.
	name, _, err := dns.UnpackDomainName(raw, 5)
	if err != nil {
		return DSYNCRecord{}, fmt.Errorf("dsync target unpack: %w", err)
	}
	rec.Target = name

	return rec, nil
}

// ParseRFC3597 parses a *dns.RFC3597 record into a DSYNCRecord.
// Returns an error if the record's Rrtype is not TypeDSYNC.
func ParseRFC3597(rr *dns.RFC3597) (DSYNCRecord, error) {
	if rr.Hdr.Rrtype != TypeDSYNC {
		return DSYNCRecord{}, fmt.Errorf("not a DSYNC record: rrtype %d", rr.Hdr.Rrtype)
	}
	return DecodeDSYNC(rr.Rdata)
}
