package cookie

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fixedClock returns a now-func pinned to t, for injecting into a Manager's
// clock seam so timestamp generation and freshness checks are deterministic.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestGenerateClientCookie(t *testing.T) {
	clientIP := net.ParseIP("192.0.2.1").To4()
	serverIP := net.ParseIP("192.0.2.53").To4()

	cookie1 := GenerateClientCookie(clientIP, serverIP)
	cookie2 := GenerateClientCookie(clientIP, serverIP)

	// Cookies should be different (include random component)
	if bytes.Equal(cookie1[:], cookie2[:]) {
		t.Error("client cookies should be unique")
	}

	// Should be correct size
	if len(cookie1) != clientCookieSize {
		t.Errorf("client cookie size = %d, want %d", len(cookie1), clientCookieSize)
	}
}

func TestGenerateServerCookie(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Should be correct size
	if len(serverCookie) != serverCookieSize {
		t.Errorf("server cookie size = %d, want %d", len(serverCookie), serverCookieSize)
	}

	// Version byte and embedded timestamp per RFC 9018 §5.
	if serverCookie[0] != cookieVersion {
		t.Errorf("server cookie version = %d, want %d", serverCookie[0], cookieVersion)
	}

	// Pin the clock so generation is deterministic, then confirm the same
	// input produces the same cookie regardless of wall-clock drift.
	m.now = fixedClock(time.Unix(1_700_000_000, 0))
	c1, _ := m.GenerateServerCookie(clientCookie, clientIP)
	c2, _ := m.GenerateServerCookie(clientCookie, clientIP)
	if !bytes.Equal(c1[:], c2[:]) {
		t.Error("same input + same clock should produce identical server cookie")
	}
}

func TestValidateServerCookie(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// Generate valid cookie
	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Should validate successfully
	err = m.ValidateServerCookie(clientCookie, serverCookie, clientIP)
	if err != nil {
		t.Errorf("ValidateServerCookie() should succeed, got error: %v", err)
	}

	// Invalid cookie should fail
	var invalidCookie [serverCookieSize]byte
	copy(invalidCookie[:], []byte("invalid!invalid!"))

	err = m.ValidateServerCookie(clientCookie, invalidCookie, clientIP)
	if err == nil {
		t.Error("ValidateServerCookie() should fail for invalid cookie")
	}

	// Wrong client IP should fail
	wrongIP := net.ParseIP("192.0.2.99").To4()
	err = m.ValidateServerCookie(clientCookie, serverCookie, wrongIP)
	if err == nil {
		t.Error("ValidateServerCookie() should fail for wrong client IP")
	}
}

func TestValidateServerCookie_Rotation(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// Generate cookie with current secret
	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Rotate secret
	if err := m.rotateSecret(); err != nil {
		t.Fatalf("rotateSecret() error: %v", err)
	}

	// Old cookie should still validate (using previous secret)
	err = m.ValidateServerCookie(clientCookie, serverCookie, clientIP)
	if err != nil {
		t.Errorf("ValidateServerCookie() should accept cookie from previous secret, got error: %v", err)
	}

	// New cookie with new secret should also validate
	newServerCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() after rotation error: %v", err)
	}

	err = m.ValidateServerCookie(clientCookie, newServerCookie, clientIP)
	if err != nil {
		t.Errorf("ValidateServerCookie() should accept new cookie, got error: %v", err)
	}
}

func TestParseCookie(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		wantClientLen  int
		wantServerLen  int
		wantErr        bool
	}{
		{
			name:          "client cookie only",
			data:          []byte{1, 2, 3, 4, 5, 6, 7, 8},
			wantClientLen: 8,
			wantServerLen: 0,
			wantErr:       false,
		},
		{
			name:          "client + server cookie",
			data:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			wantClientLen: 8,
			wantServerLen: 8,
			wantErr:       false,
		},
		{
			name:    "too short",
			data:    []byte{1, 2, 3},
			wantErr: true,
		},
		{
			name:    "server cookie too long (>32 bytes)",
			data:    make([]byte, 8+33), // client + 33 byte server
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientCookie, serverCookie, err := ParseCookie(tt.data)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(clientCookie) != tt.wantClientLen {
					t.Errorf("client cookie len = %d, want %d", len(clientCookie), tt.wantClientLen)
				}
				if len(serverCookie) != tt.wantServerLen {
					t.Errorf("server cookie len = %d, want %d", len(serverCookie), tt.wantServerLen)
				}
			}
		})
	}
}

func TestFormatCookie(t *testing.T) {
	var clientCookie [8]byte
	copy(clientCookie[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	// Client cookie only
	data := FormatCookie(clientCookie, nil)
	if len(data) != 8 {
		t.Errorf("format client only: len = %d, want 8", len(data))
	}
	if !bytes.Equal(data, clientCookie[:]) {
		t.Error("format client only: data mismatch")
	}

	// Client + server cookie
	serverCookie := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	data = FormatCookie(clientCookie, serverCookie)
	if len(data) != 16 {
		t.Errorf("format client+server: len = %d, want 16", len(data))
	}

	// Parse back
	parsedClient, parsedServer, err := ParseCookie(data)
	if err != nil {
		t.Fatalf("parse formatted cookie: %v", err)
	}
	if !bytes.Equal(parsedClient[:], clientCookie[:]) {
		t.Error("parsed client cookie mismatch")
	}
	if !bytes.Equal(parsedServer, serverCookie) {
		t.Error("parsed server cookie mismatch")
	}
}

func TestValidateQueryCookie(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		RequireValid: true,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// First query - no server cookie (should be OK)
	badCookie, err := m.ValidateQueryCookie(clientCookie, nil, clientIP)
	if badCookie || err != nil {
		t.Error("first query without server cookie should be accepted")
	}

	// Generate valid server cookie
	serverCookie, _ := m.GenerateServerCookie(clientCookie, clientIP)

	// Query with valid cookie
	badCookie, err = m.ValidateQueryCookie(clientCookie, serverCookie[:], clientIP)
	if badCookie || err != nil {
		t.Error("query with valid cookie should be accepted")
	}

	// Query with a tampered cookie (RequireValid=true should reject). Take a
	// valid 16-byte cookie and flip a hash byte.
	tampered := serverCookie
	tampered[serverCookieSize-1] ^= 0xFF
	badCookie, err = m.ValidateQueryCookie(clientCookie, tampered[:], clientIP)
	if !badCookie {
		t.Error("query with tampered cookie should trigger BADCOOKIE when RequireValid=true")
	}
}

func TestValidateQueryCookie_NotRequired(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		RequireValid: false, // Don't require valid cookie
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// Tampered 16-byte cookie but RequireValid=false: accept anyway.
	valid, _ := m.GenerateServerCookie(clientCookie, clientIP)
	tampered := valid
	tampered[serverCookieSize-1] ^= 0xFF
	badCookie, err := m.ValidateQueryCookie(clientCookie, tampered[:], clientIP)
	if badCookie {
		t.Error("invalid cookie should be accepted when RequireValid=false")
	}
}

func TestClusterSecret(t *testing.T) {
	// Create shared cluster secret
	clusterSecret := []byte("shared-cluster-secret-1234567890")

	cfg1 := Config{
		Enabled:       true,
		ClusterSecret: clusterSecret,
	}
	m1, err := NewManager(cfg1)
	if err != nil {
		t.Fatalf("NewManager(m1) error: %v", err)
	}

	cfg2 := Config{
		Enabled:       true,
		ClusterSecret: clusterSecret,
	}
	m2, err := NewManager(cfg2)
	if err != nil {
		t.Fatalf("NewManager(m2) error: %v", err)
	}

	// Pin both clocks so the embedded timestamps match regardless of when each
	// GenerateServerCookie call lands.
	pinned := fixedClock(time.Unix(1_700_000_000, 0))
	m1.now = pinned
	m2.now = pinned

	// Both servers should generate same server cookie
	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	cookie1, err := m1.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("m1.GenerateServerCookie() error: %v", err)
	}

	cookie2, err := m2.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("m2.GenerateServerCookie() error: %v", err)
	}

	// Cookies should match (same secret)
	if !bytes.Equal(cookie1[:], cookie2[:]) {
		t.Error("servers with same cluster secret should generate same cookie")
	}

	// Each server should validate the other's cookies
	err = m1.ValidateServerCookie(clientCookie, cookie2, clientIP)
	if err != nil {
		t.Errorf("m1 should validate m2's cookie: %v", err)
	}

	err = m2.ValidateServerCookie(clientCookie, cookie1, clientIP)
	if err != nil {
		t.Errorf("m2 should validate m1's cookie: %v", err)
	}
}

func TestCookiesDisabled(t *testing.T) {
	cfg := Config{
		Enabled: false, // Cookies disabled
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	var serverCookie [8]byte

	// Should always accept when disabled
	badCookie, err := m.ValidateQueryCookie(clientCookie, serverCookie[:], clientIP)
	if badCookie || err != nil {
		t.Error("disabled cookies should always accept")
	}
}

// TestValidateServerCookie_ValidLongAfterMinting proves the RFC 9018 fix: a
// cookie minted at time T still validates minutes later, because validation
// reads the embedded timestamp rather than re-hashing with the current second.
// The pre-fix implementation failed ~1 second after minting.
func TestValidateServerCookie_ValidLongAfterMinting(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	base := time.Unix(1_700_000_000, 0)
	m.now = fixedClock(base)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Advance the clock well beyond one second (5 minutes) but within the
	// 1-hour validity window.
	m.now = fixedClock(base.Add(5 * time.Minute))

	if err := m.ValidateServerCookie(clientCookie, serverCookie, clientIP); err != nil {
		t.Errorf("cookie minted 5 minutes ago should still validate, got: %v", err)
	}
}

// TestValidateServerCookie_Expired proves a cookie older than
// serverCookieValidFor is rejected with ErrExpiredCookie.
func TestValidateServerCookie_Expired(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	base := time.Unix(1_700_000_000, 0)
	m.now = fixedClock(base)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Jump past the validity window (1h + 1m).
	m.now = fixedClock(base.Add(serverCookieValidFor + time.Minute))

	err = m.ValidateServerCookie(clientCookie, serverCookie, clientIP)
	if err != ErrExpiredCookie {
		t.Errorf("expired cookie should return ErrExpiredCookie, got: %v", err)
	}
}

// TestValidateServerCookie_FutureBeyondSkew proves a cookie whose embedded
// timestamp is further in the future than the allowed skew is rejected.
func TestValidateServerCookie_FutureBeyondSkew(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	base := time.Unix(1_700_000_000, 0)
	m.now = fixedClock(base)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// Mint a cookie stamped in the future, then validate "now".
	future := base.Add(serverCookieMaxSkew + time.Minute)
	m.now = fixedClock(future)
	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	m.now = fixedClock(base)
	err = m.ValidateServerCookie(clientCookie, serverCookie, clientIP)
	if err != ErrExpiredCookie {
		t.Errorf("future cookie beyond skew should return ErrExpiredCookie, got: %v", err)
	}
}

// TestValidateServerCookie_TamperedHash proves a cookie with a modified hash is
// rejected even though its embedded timestamp is fresh.
func TestValidateServerCookie_TamperedHash(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	base := time.Unix(1_700_000_000, 0)
	m.now = fixedClock(base)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Flip a byte in the hash region (bytes 8-15); timestamp stays fresh.
	tampered := serverCookie
	tampered[serverCookieMetaSize] ^= 0x01

	err = m.ValidateServerCookie(clientCookie, tampered, clientIP)
	if err != ErrInvalidServerCookie {
		t.Errorf("tampered hash should return ErrInvalidServerCookie, got: %v", err)
	}
}

// TestServerCookieLayout verifies the on-the-wire byte layout matches RFC 9018.
func TestServerCookieLayout(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	ts := time.Unix(1_700_000_000, 0)
	m.now = fixedClock(ts)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	sc, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	if len(sc) != 16 {
		t.Fatalf("server cookie length = %d, want 16", len(sc))
	}
	if sc[0] != cookieVersion {
		t.Errorf("byte 0 (version) = %d, want %d", sc[0], cookieVersion)
	}
	if sc[1] != 0 || sc[2] != 0 || sc[3] != 0 {
		t.Errorf("bytes 1-3 (reserved) = %v, want zero", sc[1:4])
	}
	gotTS := binary.BigEndian.Uint32(sc[4:8])
	if gotTS != uint32(ts.Unix()) {
		t.Errorf("embedded timestamp = %d, want %d", gotTS, uint32(ts.Unix()))
	}
}

// Benchmark cookie generation
func BenchmarkGenerateServerCookie(b *testing.B) {
	cfg := Config{Enabled: true}
	m, _ := NewManager(cfg)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.GenerateServerCookie(clientCookie, clientIP)
	}
}

// Benchmark cookie validation
func BenchmarkValidateServerCookie(b *testing.B) {
	cfg := Config{Enabled: true}
	m, _ := NewManager(cfg)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	serverCookie, _ := m.GenerateServerCookie(clientCookie, clientIP)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ValidateServerCookie(clientCookie, serverCookie, clientIP)
	}
}
