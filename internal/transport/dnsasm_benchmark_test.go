package transport

import (
	"net"
	"testing"

	dnsasm "github.com/afterdarksys/dnsscienced/dnsasm/go"
	"github.com/afterdarksys/dnsscienced/internal/engine"
)

// Sample DNS query packet for benchmarking
var benchmarkQuery = []byte{
	// Header
	0x12, 0x34, // ID
	0x01, 0x00, // Flags: RD=1
	0x00, 0x01, // QDCOUNT
	0x00, 0x00, // ANCOUNT
	0x00, 0x00, // NSCOUNT
	0x00, 0x00, // ARCOUNT
	// Question: www.example.com A IN
	0x03, 'w', 'w', 'w',
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,       // Root label
	0x00, 0x01, // QTYPE: A
	0x00, 0x01, // QCLASS: IN
}

// BenchmarkDNSASMParsing benchmarks just the DNSASM parsing (no network)
func BenchmarkDNSASMParsing(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		header, _ := dnsasm.ParseHeader(benchmarkQuery)
		if header.QDCount > 0 {
			_, _, _ = dnsasm.ParseQuestion(benchmarkQuery, 12)
		}
	}
}

// BenchmarkFullPipeline benchmarks the full security pipeline (no network)
func BenchmarkFullPipeline(b *testing.B) {
	acl := engine.NewACL(true)
	limiter := engine.NewRateLimiter(engine.RateLimiterConfig{
		QueriesPerSecond: 1000000, // Very high for benchmarking
		BurstSize:        1000000,
	})
	rpz := engine.NewRPZAggregate()
	clientIP := net.ParseIP("192.168.1.100")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 1. Parse header
		header, err := dnsasm.ParseHeader(benchmarkQuery)
		if err != nil || header.QR {
			continue
		}

		// 2. ACL check
		if !acl.IsAllowed(clientIP) {
			continue
		}

		// 3. Rate limit check
		if !limiter.Allow(clientIP) {
			continue
		}

		// 4. Parse question
		question, _, err := dnsasm.ParseQuestion(benchmarkQuery, 12)
		if err != nil {
			continue
		}

		// 5. RPZ check
		_, action := rpz.Check(question.Name + ".")
		if action != engine.RPZActionPassthru && action != engine.RPZActionNone {
			continue
		}

		// Would resolve here...
	}
}

// BenchmarkParallelPipeline benchmarks parallel processing
func BenchmarkParallelPipeline(b *testing.B) {
	acl := engine.NewACL(true)
	limiter := engine.NewRateLimiter(engine.RateLimiterConfig{
		QueriesPerSecond: 100000000,
		BurstSize:        100000000,
	})
	rpz := engine.NewRPZAggregate()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		clientIP := net.ParseIP("192.168.1.100")
		for pb.Next() {
			header, err := dnsasm.ParseHeader(benchmarkQuery)
			if err != nil || header.QR {
				continue
			}

			if !acl.IsAllowed(clientIP) {
				continue
			}

			if !limiter.Allow(clientIP) {
				continue
			}

			question, _, err := dnsasm.ParseQuestion(benchmarkQuery, 12)
			if err != nil {
				continue
			}

			_, action := rpz.Check(question.Name + ".")
			_ = action
		}
	})
}
