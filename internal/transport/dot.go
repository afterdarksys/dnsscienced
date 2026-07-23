// Package transport provides DNS transport listeners for various protocols.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Handler is the interface for handling DNS messages.
type Handler interface {
	// HandleDNS processes a DNS query and returns a response.
	HandleDNS(ctx context.Context, req *dns.Msg, remoteAddr net.Addr) (*dns.Msg, error)
}

// HandlerFunc is an adapter to allow ordinary functions as DNS handlers.
type HandlerFunc func(ctx context.Context, req *dns.Msg, remoteAddr net.Addr) (*dns.Msg, error)

func (f HandlerFunc) HandleDNS(ctx context.Context, req *dns.Msg, remoteAddr net.Addr) (*dns.Msg, error) {
	return f(ctx, req, remoteAddr)
}

// DoTListener implements a DNS-over-TLS listener per RFC 7858.
type DoTListener struct {
	mu       sync.Mutex
	addr     string
	config   *tls.Config
	listener net.Listener
	handler  Handler
	timeout  time.Duration
	running  bool
	wg       sync.WaitGroup
}

// DoTConfig holds configuration for the DoT listener.
type DoTConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Address   string        `yaml:"address"` // Listen address (default ":853")
	TLSConfig *tls.Config   // TLS configuration
	CertFile  string        `yaml:"cert_file"` // Path to TLS certificate (if TLSConfig not provided)
	KeyFile   string        `yaml:"key_file"`  // Path to TLS private key (if TLSConfig not provided)
	Timeout   time.Duration `yaml:"timeout"`   // Connection timeout
}

// NewDoTListener creates a new DNS-over-TLS listener.
func NewDoTListener(cfg DoTConfig, handler Handler) (*DoTListener, error) {
	if handler == nil {
		return nil, fmt.Errorf("DNS handler is required")
	}
	if cfg.Address == "" {
		cfg.Address = ":853"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	var tlsConfig *tls.Config
	if cfg.TLSConfig != nil {
		tlsConfig = cfg.TLSConfig
	} else if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		return nil, fmt.Errorf("TLS configuration required: provide TLSConfig or CertFile/KeyFile")
	}
	tlsConfig = tlsConfig.Clone()
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}

	return &DoTListener{
		addr:    cfg.Address,
		config:  tlsConfig,
		handler: handler,
		timeout: cfg.Timeout,
	}, nil
}

// Start begins accepting connections.
func (l *DoTListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("listener already running")
	}

	listener, err := tls.Listen("tcp", l.addr, l.config)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener: %w", err)
	}

	l.listener = listener
	l.running = true

	go l.acceptLoop()
	return nil
}

// Stop gracefully stops the listener.
func (l *DoTListener) Stop() error {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return nil
	}
	l.running = false
	err := l.listener.Close()
	l.mu.Unlock()

	l.wg.Wait()
	return err
}

// Addr returns the listener's address.
func (l *DoTListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Addr()
	}
	return nil
}

func (l *DoTListener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			l.mu.Lock()
			running := l.running
			l.mu.Unlock()
			if !running {
				return // Listener was stopped
			}
			continue
		}

		l.wg.Add(1)
		go func(c net.Conn) {
			defer l.wg.Done()
			l.handleConnection(c)
		}(conn)
	}
}

func (l *DoTListener) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set read deadline for the initial query
	if err := conn.SetReadDeadline(time.Now().Add(l.timeout)); err != nil {
		return
	}

	for {
		// Read DNS message length (2-byte prefix per RFC 7858)
		length := make([]byte, 2)
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}

		msgLen := int(length[0])<<8 | int(length[1])
		if msgLen > 65535 || msgLen == 0 {
			return
		}

		// Read DNS message
		msgBytes := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBytes); err != nil {
			return
		}

		// Parse DNS message
		req := new(dns.Msg)
		if err := req.Unpack(msgBytes); err != nil {
			continue
		}

		// Handle the query
		ctx, cancel := context.WithTimeout(context.Background(), l.timeout)
		resp, err := l.handler.HandleDNS(ctx, req, conn.RemoteAddr())
		cancel()
		if err != nil {
			// Send SERVFAIL
			resp = new(dns.Msg)
			resp.SetRcode(req, dns.RcodeServerFailure)
		}

		// Pack and send response
		respBytes, err := resp.Pack()
		if err != nil {
			continue
		}

		// Write length prefix
		respLen := len(respBytes)
		header := []byte{byte(respLen >> 8), byte(respLen)}
		if err := conn.SetWriteDeadline(time.Now().Add(l.timeout)); err != nil {
			return
		}
		if _, err := io.Copy(conn, io.MultiReader(
			bytes.NewReader(header),
			bytes.NewReader(respBytes),
		)); err != nil {
			return
		}

		// Reset deadline for next query
		if err := conn.SetReadDeadline(time.Now().Add(l.timeout)); err != nil {
			return
		}
	}
}
