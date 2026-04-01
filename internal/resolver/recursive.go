package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/dnsscience/dnsscienced/internal/cache"
	"github.com/dnsscience/dnsscienced/internal/cookie"
	"github.com/dnsscience/dnsscienced/internal/packet"
	"github.com/dnsscience/dnsscienced/internal/pool"
	"github.com/dnsscience/dnsscienced/internal/random"
	"github.com/dnsscience/dnsscienced/internal/rrl"
	"github.com/dnsscience/dnsscienced/internal/worker"
	"github.com/miekg/dns"
)

var (
	// Root hints (simplified - real version would load from file)
	rootServers = []string{
		"198.41.0.4:53",     // a.root-servers.net
		"199.9.14.201:53",   // b.root-servers.net
		"192.33.4.12:53",    // c.root-servers.net
		"199.7.91.13:53",    // d.root-servers.net
		"192.203.230.10:53", // e.root-servers.net
		"192.5.5.241:53",    // f.root-servers.net
		"192.112.36.4:53",   // g.root-servers.net
		"198.97.190.53:53",  // h.root-servers.net
		"192.36.148.17:53",  // i.root-servers.net
		"192.58.128.30:53",  // j.root-servers.net
		"193.0.14.129:53",   // k.root-servers.net
		"199.7.83.42:53",    // l.root-servers.net
		"202.12.27.33:53",   // m.root-servers.net
	}

	ErrMaxIterations = errors.New("max iterations reached")
	ErrNoNameservers = errors.New("no nameservers available")
	ErrTimeout       = errors.New("query timeout")
)

// Config holds resolver configuration
type Config struct {
	// Cache configuration
	CacheConfig cache.Config `yaml:"cache"`

	// Worker pool for concurrent queries
	Workers int `yaml:"workers"`

	// Query timeout
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// Max iterations for iterative resolution
	MaxIterations int `yaml:"max_iterations"`

	// Enable DNS cookies
	EnableCookies bool          `yaml:"enable_cookies"`
	CookieConfig  cookie.Config `yaml:"cookies"`

	// Enable RRL
	EnableRRL bool       `yaml:"enable_rrl"`
	RRLConfig rrl.Config `yaml:"rrl"`
}

// Recursive implements a full recursive DNS resolver
type Recursive struct {
	cache      *cache.ShardedCache
	workerPool *worker.Pool
	cookies    *cookie.Manager
	rrl        *rrl.Limiter

	cfg Config

	// UDP client with randomized source port
	client *dns.Client
}

// NewRecursive creates a new recursive resolver
func NewRecursive(cfg Config) (*Recursive, error) {
	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = 5 * time.Second
	}
	if cfg.MaxIterations == 0 {
		cfg.MaxIterations = 20
	}
	if cfg.Workers == 0 {
		cfg.Workers = 100
	}

	r := &Recursive{
		cache: cache.NewShardedCache(cfg.CacheConfig),
		workerPool: worker.NewPool(worker.Config{
			Workers:   cfg.Workers,
			QueueSize: cfg.Workers * 10,
		}),
		client: &dns.Client{
			Timeout: cfg.QueryTimeout,
			Net:     "udp",
		},
		cfg: cfg,
	}

	// Initialize cookies if enabled
	if cfg.EnableCookies {
		var err error
		r.cookies, err = cookie.NewManager(cfg.CookieConfig)
		if err != nil {
			return nil, fmt.Errorf("init cookies: %w", err)
		}
	}

	// Initialize RRL if enabled
	if cfg.EnableRRL {
		r.rrl = rrl.NewLimiter(cfg.RRLConfig)
	}

	return r, nil
}

// Resolve performs recursive resolution for a query
func (r *Recursive) Resolve(ctx context.Context, q *dns.Msg, clientIP net.IP) (*dns.Msg, error) {
	if len(q.Question) == 0 {
		return nil, errors.New("no question in query")
	}

	question := q.Question[0]

	// Check cache first
	cacheKey := packet.HashQuery(question.Name, question.Qtype, question.Qclass)
	if entry, ok := r.cache.Get(cacheKey); ok && !entry.IsExpired() {
		// Cache hit!
		resp := pool.GetMessage()
		defer pool.PutMessage(resp)

		if err := resp.Unpack(entry.Data); err == nil {
			resp.Id = q.Id // Use query's transaction ID
			return resp.Copy(), nil
		}
	}

	// Cache miss - perform iterative resolution
	resp, err := r.resolveIterative(ctx, question.Name, question.Qtype, question.Qclass)
	if err != nil {
		return nil, err
	}

	resp.Id = q.Id
	resp.RecursionAvailable = true

	// Cache the response
	if packed, err := resp.Pack(); err == nil {
		r.cache.Set(cacheKey, &cache.Entry{
			Data:      packed,
			ExpiresAt: time.Now().Add(time.Duration(getTTL(resp)) * time.Second),
			OrigTTL:   getTTL(resp),
			QName:     question.Name,
			QType:     question.Qtype,
			QClass:    question.Qclass,
		})
	}

	return resp, nil
}

// resolveIterative performs iterative resolution starting from root
func (r *Recursive) resolveIterative(ctx context.Context, qname string, qtype, qclass uint16) (*dns.Msg, error) {
	nameservers := rootServers
	iterations := 0

	for iterations < r.cfg.MaxIterations {
		iterations++

		// Query one of the nameservers
		resp, err := r.queryNameserver(ctx, nameservers[0], qname, qtype, qclass)
		if err != nil {
			// Try next nameserver
			if len(nameservers) > 1 {
				nameservers = nameservers[1:]
				continue
			}
			return nil, fmt.Errorf("all nameservers failed: %w", err)
		}

		// Check if we got an answer
		if len(resp.Answer) > 0 {
			return resp, nil
		}

		// Check for NXDOMAIN
		if resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}

		// Follow referral (NS records in Authority section)
		if len(resp.Ns) > 0 {
			var newNameservers []string

			// Extract NS records
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					// Need to resolve NS name to IP (glue records in Additional)
					nsIP := r.findGlue(resp, ns.Ns)
					if nsIP != "" {
						newNameservers = append(newNameservers, nsIP+":53")
					}
				}
			}

			if len(newNameservers) == 0 {
				return nil, ErrNoNameservers
			}

			nameservers = newNameservers
			continue
		}

		// No answer, no referral - return what we have
		return resp, nil
	}

	return nil, ErrMaxIterations
}

// queryNameserver sends a query to a specific nameserver
func (r *Recursive) queryNameserver(ctx context.Context, ns string, qname string, qtype, qclass uint16) (*dns.Msg, error) {
	msg := pool.GetMessage()
	defer pool.PutMessage(msg)

	msg.Id = random.TransactionID()
	msg.RecursionDesired = false // Iterative queries don't set RD
	msg.Question = []dns.Question{{
		Name:   qname,
		Qtype:  qtype,
		Qclass: qclass,
	}}
	msg.SetEdns0(4096, false)

	// Send query with timeout
	queryCtx, cancel := context.WithTimeout(ctx, r.cfg.QueryTimeout)
	defer cancel()

	resp, _, err := r.client.ExchangeContext(queryCtx, msg, ns)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// findGlue looks for glue records (A/AAAA) in Additional section
func (r *Recursive) findGlue(msg *dns.Msg, nsName string) string {
	for _, rr := range msg.Extra {
		switch record := rr.(type) {
		case *dns.A:
			if record.Hdr.Name == nsName {
				return record.A.String()
			}
		case *dns.AAAA:
			if record.Hdr.Name == nsName {
				return record.AAAA.String()
			}
		}
	}
	return ""
}

// getTTL extracts the minimum TTL from a response
func getTTL(msg *dns.Msg) uint32 {
	minTTL := uint32(3600) // Default 1 hour

	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	return minTTL
}

// Close stops the resolver
func (r *Recursive) Close() error {
	r.cache.Close()
	r.workerPool.Close()
	if r.rrl != nil {
		r.rrl.Close()
	}
	return nil
}

// Stats returns resolver statistics
type Stats struct {
	Cache cache.Stats
	Pool  worker.Stats
	RRL   *rrl.Stats
}

// GetStats returns current statistics
func (r *Recursive) GetStats() Stats {
	s := Stats{
		Cache: r.cache.GetStats(),
		Pool:  r.workerPool.GetStats(),
	}

	if r.rrl != nil {
		rrlStats := r.rrl.GetStats()
		s.RRL = &rrlStats
	}

	return s
}
