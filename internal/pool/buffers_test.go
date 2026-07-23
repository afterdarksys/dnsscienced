package pool

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMessagePool(t *testing.T) {
	// Get message
	msg := GetMessage()
	if msg == nil {
		t.Fatal("GetMessage() returned nil")
	}

	// Use it
	msg.Id = 0x1234
	msg.SetQuestion("example.com.", dns.TypeA)

	// Return it
	PutMessage(msg)

	// Get again - should be reset
	msg2 := GetMessage()
	if msg2.Id != 0 {
		t.Errorf("message not reset: Id = %d, want 0", msg2.Id)
	}
	if len(msg2.Question) != 0 {
		t.Errorf("message not reset: Question len = %d, want 0", len(msg2.Question))
	}
}

func TestSmallBufferPool(t *testing.T) {
	buf := GetSmallBuffer()
	if len(buf) != SmallBufferSize {
		t.Errorf("buffer size = %d, want %d", len(buf), SmallBufferSize)
	}

	// Write to it
	copy(buf, []byte("test data"))

	// Return it
	PutSmallBuffer(buf)

	// Get again
	buf2 := GetSmallBuffer()
	if len(buf2) != SmallBufferSize {
		t.Errorf("buffer size = %d, want %d", len(buf2), SmallBufferSize)
	}
}

func TestMediumBufferPool(t *testing.T) {
	buf := GetMediumBuffer()
	if len(buf) != MediumBufferSize {
		t.Errorf("buffer size = %d, want %d", len(buf), MediumBufferSize)
	}

	PutMediumBuffer(buf)

	buf2 := GetMediumBuffer()
	if len(buf2) != MediumBufferSize {
		t.Errorf("buffer size = %d, want %d", len(buf2), MediumBufferSize)
	}
}

func TestLargeBufferPool(t *testing.T) {
	buf := GetLargeBuffer()
	if len(buf) != LargeBufferSize {
		t.Errorf("buffer size = %d, want %d", len(buf), LargeBufferSize)
	}

	PutLargeBuffer(buf)

	buf2 := GetLargeBuffer()
	if len(buf2) != LargeBufferSize {
		t.Errorf("buffer size = %d, want %d", len(buf2), LargeBufferSize)
	}
}

func TestGetBuffer(t *testing.T) {
	tests := []struct {
		size        int
		expectedCap int
	}{
		{100, SmallBufferSize},
		{512, SmallBufferSize},
		{1024, MediumBufferSize},
		{4096, MediumBufferSize},
		{8192, LargeBufferSize},
		{65535, LargeBufferSize},
	}

	for _, tt := range tests {
		buf := GetBuffer(tt.size)
		if cap(buf) != tt.expectedCap {
			t.Errorf("GetBuffer(%d) cap = %d, want %d", tt.size, cap(buf), tt.expectedCap)
		}
		PutBuffer(buf)
	}
}

func TestPutBuffer(t *testing.T) {
	// Should handle different sizes correctly
	small := GetSmallBuffer()
	PutBuffer(small) // Should go to SmallBufferPool

	medium := GetMediumBuffer()
	PutBuffer(medium) // Should go to MediumBufferPool

	large := GetLargeBuffer()
	PutBuffer(large) // Should go to LargeBufferPool

	// Weird size - should be ignored
	weird := make([]byte, 1234)
	PutBuffer(weird) // Should not panic
}

func TestBufferPoolHotPathDoesNotAllocate(t *testing.T) {
	for _, size := range []int{SmallBufferSize, MediumBufferSize, LargeBufferSize} {
		buf := GetBuffer(size)
		PutBuffer(buf)
		if allocs := testing.AllocsPerRun(1000, func() {
			hot := GetBuffer(size)
			PutBuffer(hot)
		}); allocs != 0 {
			t.Fatalf("GetBuffer/PutBuffer size %d allocations = %.1f, want 0", size, allocs)
		}
	}
}

func TestGetPackBufferReservesFramingAndCompressionSpace(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.", dns.TypeA)

	buf := GetPackBuffer(msg)
	if len(buf)-2 < msg.Len()+1 {
		t.Fatalf("pack buffer after framing = %d, want at least %d", len(buf)-2, msg.Len()+1)
	}
	PutBuffer(buf)

	msg.Compress = true
	buf = GetPackBuffer(msg)
	if cap(buf) < MediumBufferSize {
		t.Fatalf("compressed pack buffer capacity = %d, want at least %d", cap(buf), MediumBufferSize)
	}
	PutBuffer(buf)
}

func TestPutMessage_Nil(t *testing.T) {
	// Should not panic
	PutMessage(nil)
}

func TestPutSmallBuffer_Undersized(t *testing.T) {
	// Should not panic or pool undersized buffer
	small := make([]byte, 100)
	PutSmallBuffer(small)
}

func TestResetPools(t *testing.T) {
	// Get some objects
	msg := GetMessage()
	buf := GetSmallBuffer()

	// Reset pools
	ResetPools()

	// Should still work
	msg2 := GetMessage()
	if msg2 == nil {
		t.Error("GetMessage() failed after ResetPools")
	}

	buf2 := GetSmallBuffer()
	if len(buf2) != SmallBufferSize {
		t.Error("GetSmallBuffer() failed after ResetPools")
	}

	// Clean up
	PutMessage(msg)
	PutMessage(msg2)
	PutSmallBuffer(buf)
	PutSmallBuffer(buf2)
}

func TestMessageReset(t *testing.T) {
	msg := GetMessage()

	// Set all fields
	msg.Id = 0x1234
	msg.Response = true
	msg.Opcode = dns.OpcodeQuery
	msg.Authoritative = true
	msg.Truncated = true
	msg.RecursionDesired = true
	msg.RecursionAvailable = true
	msg.AuthenticatedData = true
	msg.CheckingDisabled = true
	msg.Rcode = dns.RcodeServerFailure

	msg.Question = append(msg.Question, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})

	// Return to pool (should reset)
	PutMessage(msg)

	// Get again
	msg2 := GetMessage()

	// Verify all fields are reset
	if msg2.Id != 0 {
		t.Errorf("Id not reset: got %d", msg2.Id)
	}
	if msg2.Response {
		t.Error("Response not reset")
	}
	if msg2.Opcode != 0 {
		t.Error("Opcode not reset")
	}
	if msg2.Authoritative {
		t.Error("Authoritative not reset")
	}
	if msg2.Truncated {
		t.Error("Truncated not reset")
	}
	if msg2.RecursionDesired {
		t.Error("RecursionDesired not reset")
	}
	if msg2.RecursionAvailable {
		t.Error("RecursionAvailable not reset")
	}
	if msg2.AuthenticatedData {
		t.Error("AuthenticatedData not reset")
	}
	if msg2.CheckingDisabled {
		t.Error("CheckingDisabled not reset")
	}
	if msg2.Rcode != 0 {
		t.Errorf("Rcode not reset: got %d", msg2.Rcode)
	}
	if len(msg2.Question) != 0 {
		t.Errorf("Question not reset: len = %d", len(msg2.Question))
	}

	PutMessage(msg2)
}

// Benchmark message pool
func BenchmarkMessagePool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		msg := GetMessage()
		msg.SetQuestion("example.com.", dns.TypeA)
		PutMessage(msg)
	}
}

// Benchmark without pool (for comparison)
func BenchmarkMessageNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
	}
}

// Benchmark small buffer pool
func BenchmarkSmallBufferPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf := GetSmallBuffer()
		PutSmallBuffer(buf)
	}
}

// Benchmark medium buffer pool
func BenchmarkMediumBufferPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf := GetMediumBuffer()
		PutMediumBuffer(buf)
	}
}

// Benchmark large buffer pool
func BenchmarkLargeBufferPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf := GetLargeBuffer()
		PutLargeBuffer(buf)
	}
}

// Benchmark intelligent buffer selection
func BenchmarkGetBuffer(b *testing.B) {
	sizes := []int{512, 1024, 4096, 8192}

	for _, size := range sizes {
		b.Run("size="+string(rune(size)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				buf := GetBuffer(size)
				PutBuffer(buf)
			}
		})
	}
}
