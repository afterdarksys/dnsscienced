package dsync_test

import (
	"testing"

	"github.com/afterdarksys/dnsscienced/internal/dsync"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDSYNCCodec_RoundTrip verifies that EncodeDSYNC followed by DecodeDSYNC
// returns the original DSYNCRecord unchanged (DSYNC-01).
func TestDSYNCCodec_RoundTrip(t *testing.T) {
	rec := dsync.DSYNCRecord{
		RRtype: 59, // dns.TypeCDS
		Scheme: dsync.DSYNCSchemeNOTIFY,
		Port:   53,
		Target: "ns1.example.com.",
	}

	encoded, err := dsync.EncodeDSYNC(rec)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded, "encoded hex string must not be empty")

	decoded, err := dsync.DecodeDSYNC(encoded)
	require.NoError(t, err)
	assert.Equal(t, rec.RRtype, decoded.RRtype)
	assert.Equal(t, rec.Scheme, decoded.Scheme)
	assert.Equal(t, rec.Port, decoded.Port)
	assert.Equal(t, rec.Target, decoded.Target)
}

// TestDSYNCDecodeTooShort verifies that DecodeDSYNC returns an error for rdata
// shorter than 6 bytes (DSYNC-02).
func TestDSYNCDecodeTooShort(t *testing.T) {
	// "0a0b" = 2 bytes, which is < 6 minimum
	_, err := dsync.DecodeDSYNC("0a0b")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestDSYNCCodec_CSYNC verifies round-trip for a CSYNC (type 62) DSYNC record.
func TestDSYNCCodec_CSYNC(t *testing.T) {
	rec := dsync.DSYNCRecord{
		RRtype: 62, // dns.TypeCSYNC
		Scheme: dsync.DSYNCSchemeNOTIFY,
		Port:   5359,
		Target: "scanner.example.net.",
	}

	encoded, err := dsync.EncodeDSYNC(rec)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	decoded, err := dsync.DecodeDSYNC(encoded)
	require.NoError(t, err)
	assert.Equal(t, rec.RRtype, decoded.RRtype)
	assert.Equal(t, rec.Scheme, decoded.Scheme)
	assert.Equal(t, rec.Port, decoded.Port)
	assert.Equal(t, rec.Target, decoded.Target)
}

// TestParseRFC3597 verifies that ParseRFC3597 correctly decodes a valid DSYNC record
// from a *dns.RFC3597 and returns an error for wrong Rrtype.
func TestParseRFC3597(t *testing.T) {
	// First encode a record to get valid hex rdata
	rec := dsync.DSYNCRecord{
		RRtype: 59, // dns.TypeCDS
		Scheme: dsync.DSYNCSchemeNOTIFY,
		Port:   53,
		Target: "ns1.example.com.",
	}
	encoded, err := dsync.EncodeDSYNC(rec)
	require.NoError(t, err)

	// Test with correct Rrtype == TypeDSYNC (66)
	rfc := &dns.RFC3597{
		Hdr:   dns.RR_Header{Rrtype: dsync.TypeDSYNC},
		Rdata: encoded,
	}
	parsed, err := dsync.ParseRFC3597(rfc)
	require.NoError(t, err)
	assert.Equal(t, rec.RRtype, parsed.RRtype)
	assert.Equal(t, rec.Scheme, parsed.Scheme)
	assert.Equal(t, rec.Port, parsed.Port)
	assert.Equal(t, rec.Target, parsed.Target)

	// Test with wrong Rrtype — should return error
	rfcWrong := &dns.RFC3597{
		Hdr:   dns.RR_Header{Rrtype: 1}, // TypeA, not TypeDSYNC
		Rdata: encoded,
	}
	_, err = dsync.ParseRFC3597(rfcWrong)
	require.Error(t, err)
}

// TestDSYNCSchemeZeroIgnored verifies that Scheme=0 encodes and decodes without error.
// Callers are responsible for skipping null-scheme records; the codec itself does not error.
func TestDSYNCSchemeZeroIgnored(t *testing.T) {
	rec := dsync.DSYNCRecord{
		RRtype: 59,
		Scheme: dsync.DSYNCSchemeNull, // 0 = null (no-op)
		Port:   53,
		Target: "ns1.example.com.",
	}

	encoded, err := dsync.EncodeDSYNC(rec)
	require.NoError(t, err)

	decoded, err := dsync.DecodeDSYNC(encoded)
	require.NoError(t, err)
	assert.Equal(t, dsync.DSYNCSchemeNull, decoded.Scheme)
	assert.Equal(t, uint16(59), decoded.RRtype)
}
