package cookie

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/dchest/siphash"
)

// RFC 7873: Domain Name System (DNS) Cookies
// RFC 9018: Interoperable Domain Name System (DNS) Server Cookies
//
// DNS Cookies provide a lightweight mechanism to defend against
// off-path attacks by allowing clients and servers to verify their
// communication partner's identity.
//
// Implementation follows BIND 9's SipHash 2-4 based approach:
// https://kb.isc.org/docs/aa-01387

var (
	ErrInvalidCookie       = errors.New("invalid cookie format")
	ErrInvalidClientCookie = errors.New("invalid client cookie")
	ErrInvalidServerCookie = errors.New("invalid server cookie")
	ErrExpiredCookie       = errors.New("server cookie expired")
	ErrBadCookie           = errors.New("bad cookie")
)

const (
	// Cookie sizes per RFC 7873 / RFC 9018
	clientCookieSize = 8 // 64 bits

	// RFC 9018 §5 server-cookie layout (16 bytes):
	//   byte 0:      Version (1)
	//   bytes 1-3:   Reserved (zero)
	//   bytes 4-7:   Timestamp (uint32 Unix seconds, big-endian)
	//   bytes 8-15:  Hash (MAC over Client-Cookie || Version || Reserved ||
	//                Timestamp || Client-IP, keyed by the server secret)
	serverCookieMetaSize = 8                                      // version + reserved + timestamp
	serverCookieHashSize = 8                                      // MAC output (SipHash-2-4)
	serverCookieSize     = serverCookieMetaSize + serverCookieHashSize // 16 bytes
	cookieTotalSize      = clientCookieSize + serverCookieSize    // 24 bytes

	// Version field
	cookieVersion = 1

	// Server cookie validity period (per BIND 9 default)
	serverCookieValidFor = 1 * time.Hour

	// Allowed clock skew for cookies whose embedded timestamp is in the
	// future relative to this server (accommodates modest clock drift in a
	// cluster). Cookies further ahead than this are rejected.
	serverCookieMaxSkew = 5 * time.Minute

	// Secret rotation interval
	secretRotationInterval = 24 * time.Hour
)

// Manager handles DNS cookie generation and validation
type Manager struct {
	mu sync.RWMutex

	// Current and previous secrets for rotation
	currentSecret  [16]byte
	previousSecret [16]byte
	secretTime     time.Time

	// Configuration
	enabled      bool
	requireValid bool // Require valid cookie for responses

	// Secret for cookie-secret sharing across cluster
	clusterSecret [16]byte
	useCluster    bool

	// now is a seam over time.Now so tests can control the clock used for
	// timestamp generation and freshness validation. Defaults to time.Now.
	now func() time.Time
}

// Config holds cookie manager configuration
type Config struct {
	// Enable DNS cookies
	Enabled bool `yaml:"enabled"`

	// Require valid server cookie (BADCOOKIE if missing/invalid)
	RequireValid bool `yaml:"require_valid"`

	// Cluster secret for load-balanced deployments
	// All servers in cluster must use same secret
	ClusterSecret []byte `yaml:"cluster_secret"`
}

// NewManager creates a new DNS cookie manager
func NewManager(cfg Config) (*Manager, error) {
	m := &Manager{
		enabled:      cfg.Enabled,
		requireValid: cfg.RequireValid,
		now:          time.Now,
	}

	if cfg.ClusterSecret != nil && len(cfg.ClusterSecret) >= 16 {
		// Use provided cluster secret
		copy(m.clusterSecret[:], cfg.ClusterSecret)
		m.useCluster = true
		m.currentSecret = m.clusterSecret
	} else {
		// Generate random secret
		if err := m.rotateSecret(); err != nil {
			return nil, err
		}
	}

	return m, nil
}

// rotateSecret generates a new random secret
func (m *Manager) rotateSecret() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Don't rotate cluster secrets
	if m.useCluster {
		return nil
	}

	// Move current to previous
	m.previousSecret = m.currentSecret

	// Generate new current
	_, err := rand.Read(m.currentSecret[:])
	if err != nil {
		return err
	}

	m.secretTime = time.Now()
	return nil
}

// RotateSecretPeriodically runs secret rotation in background
func (m *Manager) RotateSecretPeriodically(stop <-chan struct{}) {
	ticker := time.NewTicker(secretRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.rotateSecret()
		case <-stop:
			return
		}
	}
}

// GenerateClientCookie generates an 8-byte client cookie
// Client cookie = Hash(client-IP || server-IP || random)
// In practice, clients should generate this, but we provide for testing
func GenerateClientCookie(clientIP, serverIP []byte) [8]byte {
	var cookie [8]byte

	// Use random data as well for uniqueness
	var random [8]byte
	rand.Read(random[:])

	// SipHash-2-4 with random key
	var key [16]byte
	rand.Read(key[:])

	h := siphash.New(key[:])
	h.Write(clientIP)
	h.Write(serverIP)
	h.Write(random[:])

	binary.LittleEndian.PutUint64(cookie[:], h.Sum64())
	return cookie
}

// GenerateServerCookie generates a 16-byte server cookie per RFC 9018 §5.
// The timestamp is embedded in bytes 4-7 and the MAC (bytes 8-15) is computed
// over the client cookie, the fixed fields (version, reserved, timestamp) and
// the client IP, keyed by the current server secret.
func (m *Manager) GenerateServerCookie(clientCookie [8]byte, clientIP []byte) ([serverCookieSize]byte, error) {
	m.mu.RLock()
	secret := m.currentSecret
	m.mu.RUnlock()

	timestamp := uint32(m.now().Unix())
	return computeServerCookie(secret, clientCookie, clientIP, timestamp), nil
}

// ValidateServerCookie validates a 16-byte server cookie. It reads the
// timestamp embedded in the cookie (NOT the current wall-clock), recomputes the
// MAC using that timestamp, constant-time compares it, and enforces the
// freshness window. Both the current and previous secret are tried so cookies
// minted just before a secret rotation still validate.
func (m *Manager) ValidateServerCookie(clientCookie [8]byte, serverCookie [serverCookieSize]byte, clientIP []byte) error {
	if !m.enabled {
		return nil // Cookies disabled
	}

	// Read the embedded timestamp (bytes 4-7, big-endian).
	timestamp := binary.BigEndian.Uint32(serverCookie[4:serverCookieMetaSize])

	m.mu.RLock()
	curSecret := m.currentSecret
	prevSecret := m.previousSecret
	m.mu.RUnlock()

	// Recompute the MAC using the EMBEDDED timestamp and constant-time compare
	// the hash portion only. Try current secret first, then previous.
	expected := computeServerCookie(curSecret, clientCookie, clientIP, timestamp)
	valid := subtle_compare(serverCookie[serverCookieMetaSize:], expected[serverCookieMetaSize:])
	if !valid {
		expectedPrev := computeServerCookie(prevSecret, clientCookie, clientIP, timestamp)
		valid = subtle_compare(serverCookie[serverCookieMetaSize:], expectedPrev[serverCookieMetaSize:])
	}
	if !valid {
		return ErrInvalidServerCookie
	}

	// MAC is authentic (so the timestamp is trustworthy). Enforce freshness.
	age := m.now().Unix() - int64(timestamp)
	if age > int64(serverCookieValidFor/time.Second) {
		return ErrExpiredCookie // older than the validity window
	}
	if age < -int64(serverCookieMaxSkew/time.Second) {
		return ErrExpiredCookie // timestamp too far in the future
	}

	return nil
}

// computeServerCookie builds the full 16-byte RFC 9018 server cookie for the
// given secret, client cookie, client IP and timestamp.
func computeServerCookie(secret [16]byte, clientCookie [8]byte, clientIP []byte, timestamp uint32) [serverCookieSize]byte {
	var serverCookie [serverCookieSize]byte

	// Fixed fields: version || reserved(3) || timestamp (bytes 0-7).
	serverCookie[0] = cookieVersion
	// bytes 1-3 remain zero (reserved)
	binary.BigEndian.PutUint32(serverCookie[4:serverCookieMetaSize], timestamp)

	// MAC over Client-Cookie || Version || Reserved || Timestamp || Client-IP.
	h := siphash.New(secret[:])
	h.Write(clientCookie[:])
	h.Write(serverCookie[:serverCookieMetaSize])
	h.Write(clientIP)

	binary.LittleEndian.PutUint64(serverCookie[serverCookieMetaSize:], h.Sum64())
	return serverCookie
}

// ParseCookie extracts client and server cookies from EDNS0 COOKIE option
// Cookie format: <client-cookie (8 bytes)> [<server-cookie (8-32 bytes)>]
func ParseCookie(data []byte) (clientCookie [8]byte, serverCookie []byte, err error) {
	if len(data) < clientCookieSize {
		return clientCookie, nil, ErrInvalidClientCookie
	}

	copy(clientCookie[:], data[:clientCookieSize])

	if len(data) > clientCookieSize {
		// Server cookie present
		serverCookie = make([]byte, len(data)-clientCookieSize)
		copy(serverCookie, data[clientCookieSize:])

		// Validate server cookie size (8-32 bytes per RFC 7873)
		if len(serverCookie) < 8 || len(serverCookie) > 32 {
			return clientCookie, nil, ErrInvalidServerCookie
		}
	}

	return clientCookie, serverCookie, nil
}

// FormatCookie creates EDNS0 COOKIE option data
func FormatCookie(clientCookie [8]byte, serverCookie []byte) []byte {
	data := make([]byte, clientCookieSize+len(serverCookie))
	copy(data[:clientCookieSize], clientCookie[:])
	if len(serverCookie) > 0 {
		copy(data[clientCookieSize:], serverCookie)
	}
	return data
}

// subtle_compare does constant-time comparison
func subtle_compare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ValidateQueryCookie validates the cookie in a DNS query
// Returns whether to send BADCOOKIE response
func (m *Manager) ValidateQueryCookie(clientCookie [8]byte, serverCookie []byte, clientIP []byte) (bool, error) {
	if !m.enabled {
		return false, nil // Cookies disabled
	}

	// If no server cookie, this is first query - that's OK
	if len(serverCookie) == 0 {
		return false, nil
	}

	// Validate server cookie
	if len(serverCookie) != serverCookieSize {
		if m.requireValid {
			return true, ErrInvalidServerCookie // Send BADCOOKIE
		}
		return false, nil // Accept but don't require
	}

	var sc [serverCookieSize]byte
	copy(sc[:], serverCookie)

	err := m.ValidateServerCookie(clientCookie, sc, clientIP)
	if err != nil {
		if m.requireValid {
			return true, err // Send BADCOOKIE
		}
		return false, nil // Accept but note invalid
	}

	return false, nil // Valid cookie
}

// Statistics for monitoring
type Stats struct {
	TotalQueries       uint64
	QueriesWithCookie  uint64
	ValidCookies       uint64
	InvalidCookies     uint64
	BadCookieResponses uint64
	CookiesGenerated   uint64
}

// Stats returns cookie statistics
func (m *Manager) Stats() Stats {
	// TODO: Implement atomic counters
	return Stats{}
}
