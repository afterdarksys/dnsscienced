package pool

import (
	"sync"

	"github.com/miekg/dns"
)

// DNS message and buffer pools to reduce GC pressure
// Critical for high-performance DNS servers processing millions of queries

const (
	// Buffer sizes for different use cases
	SmallBufferSize  = 512   // UDP DNS queries (most common)
	MediumBufferSize = 4096  // EDNS0 responses
	LargeBufferSize  = 65535 // Maximum DNS message size
)

// MessagePool is a sync.Pool for dns.Msg reuse
var MessagePool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}

// GetMessage gets a message from the pool
func GetMessage() *dns.Msg {
	return MessagePool.Get().(*dns.Msg)
}

// PutMessage returns a message to the pool
// IMPORTANT: Message is reset before returning to pool
func PutMessage(msg *dns.Msg) {
	if msg == nil {
		return
	}

	// Reset the message to prevent data leakage
	// This is critical for security - don't skip this!
	msg.Id = 0
	msg.Response = false
	msg.Opcode = 0
	msg.Authoritative = false
	msg.Truncated = false
	msg.RecursionDesired = false
	msg.RecursionAvailable = false
	msg.Zero = false
	msg.AuthenticatedData = false
	msg.CheckingDisabled = false
	msg.Rcode = 0

	// Clear slices but keep capacity
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]

	MessagePool.Put(msg)
}

// SmallBufferPool for UDP queries (512 bytes)
var SmallBufferPool = sync.Pool{
	New: func() interface{} {
		return new([SmallBufferSize]byte)
	},
}

// GetSmallBuffer gets a 512-byte buffer
func GetSmallBuffer() []byte {
	return SmallBufferPool.Get().(*[SmallBufferSize]byte)[:]
}

// PutSmallBuffer returns a buffer to the pool
func PutSmallBuffer(buf []byte) {
	if cap(buf) != SmallBufferSize {
		return // Keep size classes isolated.
	}
	SmallBufferPool.Put((*[SmallBufferSize]byte)(buf[:SmallBufferSize]))
}

// MediumBufferPool for EDNS0 responses (4096 bytes)
var MediumBufferPool = sync.Pool{
	New: func() interface{} {
		return new([MediumBufferSize]byte)
	},
}

// GetMediumBuffer gets a 4096-byte buffer
func GetMediumBuffer() []byte {
	return MediumBufferPool.Get().(*[MediumBufferSize]byte)[:]
}

// PutMediumBuffer returns a buffer to the pool
func PutMediumBuffer(buf []byte) {
	if cap(buf) != MediumBufferSize {
		return
	}
	MediumBufferPool.Put((*[MediumBufferSize]byte)(buf[:MediumBufferSize]))
}

// LargeBufferPool for large responses (65535 bytes)
var LargeBufferPool = sync.Pool{
	New: func() interface{} {
		return new([LargeBufferSize]byte)
	},
}

// GetLargeBuffer gets a 65535-byte buffer
func GetLargeBuffer() []byte {
	return LargeBufferPool.Get().(*[LargeBufferSize]byte)[:]
}

// PutLargeBuffer returns a buffer to the pool
func PutLargeBuffer(buf []byte) {
	if cap(buf) != LargeBufferSize {
		return
	}
	LargeBufferPool.Put((*[LargeBufferSize]byte)(buf[:LargeBufferSize]))
}

// GetBuffer intelligently selects the right buffer size
func GetBuffer(size int) []byte {
	switch {
	case size <= SmallBufferSize:
		return GetSmallBuffer()
	case size <= MediumBufferSize:
		return GetMediumBuffer()
	default:
		return GetLargeBuffer()
	}
}

// GetPackBuffer returns a size-class buffer suitable for Msg.PackBuffer.
// Compressed messages are given at least the medium class because miekg/dns
// computes compression into a temporary map after selecting the destination
// buffer, and the uncompressed working size can exceed Msg.Len().
func GetPackBuffer(msg *dns.Msg) []byte {
	// Reserve two leading bytes as well so framed transports can pass buf[2:]
	// without losing the one-byte PackBuffer sizing margin.
	size := msg.Len() + 3
	if msg.Compress && size < MediumBufferSize {
		size = MediumBufferSize
	}
	return GetBuffer(size)
}

// PutBuffer returns a buffer to the appropriate pool
func PutBuffer(buf []byte) {
	capacity := cap(buf)
	switch {
	case capacity == SmallBufferSize:
		PutSmallBuffer(buf)
	case capacity == MediumBufferSize:
		PutMediumBuffer(buf)
	case capacity == LargeBufferSize:
		PutLargeBuffer(buf)
		// else: don't pool weird sizes
	}
}

// WriterPool is for buffered writers
// Useful for bulk zone transfers or logging
var WriterPool = sync.Pool{
	New: func() interface{} {
		return new([8192]byte)
	},
}

// GetWriterBuffer gets an 8KB writer buffer
func GetWriterBuffer() []byte {
	return WriterPool.Get().(*[8192]byte)[:]
}

// PutWriterBuffer returns writer buffer to pool
func PutWriterBuffer(buf []byte) {
	if cap(buf) == 8192 {
		WriterPool.Put((*[8192]byte)(buf[:8192]))
	}
}

// Stats tracks pool allocation statistics
// Useful for monitoring and tuning
type Stats struct {
	Gets uint64
	Puts uint64
	News uint64 // Allocations (pool miss)
}

// We could add atomic counters here for production monitoring,
// but sync.Pool doesn't expose this by default.
// In production, you'd instrument with prometheus or similar.

// ResetPools clears all pools (useful for testing or memory pressure)
func ResetPools() {
	MessagePool = sync.Pool{
		New: func() interface{} {
			return new(dns.Msg)
		},
	}

	SmallBufferPool = sync.Pool{
		New: func() interface{} {
			return new([SmallBufferSize]byte)
		},
	}

	MediumBufferPool = sync.Pool{
		New: func() interface{} {
			return new([MediumBufferSize]byte)
		},
	}

	LargeBufferPool = sync.Pool{
		New: func() interface{} {
			return new([LargeBufferSize]byte)
		},
	}

	WriterPool = sync.Pool{
		New: func() interface{} {
			return new([8192]byte)
		},
	}
}

// Example usage patterns:

// Pattern 1: DNS message processing
// msg := pool.GetMessage()
// defer pool.PutMessage(msg)
// msg.SetQuestion("example.com.", dns.TypeA)
// // ... process message ...

// Pattern 2: Buffer for packing
// buf := pool.GetSmallBuffer()
// defer pool.PutSmallBuffer(buf)
// packed, err := msg.PackBuffer(buf)

// Pattern 3: Intelligent buffer sizing
// expectedSize := 1024
// buf := pool.GetBuffer(expectedSize)
// defer pool.PutBuffer(buf)
