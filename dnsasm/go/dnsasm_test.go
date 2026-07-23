package dnsasm

import (
	"encoding/binary"
	"testing"
)

// Sample DNS query packet
var sampleQuery = []byte{
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

var benchmarkHeader Header

func TestParseHeader(t *testing.T) {
	h, err := ParseHeader(sampleQuery)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}

	if h.ID != 0x1234 {
		t.Errorf("ID = %04x, want 0x1234", h.ID)
	}
	if h.QR != false {
		t.Errorf("QR = %v, want false (query)", h.QR)
	}
	if h.RD != true {
		t.Errorf("RD = %v, want true", h.RD)
	}
	if h.QDCount != 1 {
		t.Errorf("QDCount = %d, want 1", h.QDCount)
	}
}

func TestParseQuestion(t *testing.T) {
	q, offset, err := ParseQuestion(sampleQuery, 12)
	if err != nil {
		t.Fatalf("ParseQuestion failed: %v", err)
	}

	if q.Name != "www.example.com" {
		t.Errorf("Name = %q, want %q", q.Name, "www.example.com")
	}
	if q.Type != TypeA {
		t.Errorf("Type = %d, want %d (A)", q.Type, TypeA)
	}
	if q.Class != ClassIN {
		t.Errorf("Class = %d, want %d (IN)", q.Class, ClassIN)
	}
	if offset != len(sampleQuery) {
		t.Errorf("offset = %d, want %d", offset, len(sampleQuery))
	}
}

func TestParseHeaderShort(t *testing.T) {
	_, err := ParseHeader([]byte{0x12, 0x34})
	if err != ErrShort {
		t.Errorf("expected ErrShort, got %v", err)
	}
}

func TestParseHeaderExactLength(t *testing.T) {
	h, err := ParseHeader(sampleQuery[:12:12])
	if err != nil {
		t.Fatalf("ParseHeader failed for an exact-length header: %v", err)
	}
	if h.ID != 0x1234 || h.QDCount != 1 {
		t.Fatalf("unexpected header: %+v", h)
	}
}

func TestParseHeaderIntoFields(t *testing.T) {
	wire := []byte{
		0xab, 0xcd, 0xff, 0xff,
		0, 1, 0, 2, 0, 3, 0, 4,
	}
	var h Header
	if err := ParseHeaderInto(wire, &h); err != nil {
		t.Fatalf("ParseHeaderInto failed: %v", err)
	}
	if h.ID != 0xabcd || h.Flags != 0xffff ||
		h.QDCount != 1 || h.ANCount != 2 || h.NSCount != 3 || h.ARCount != 4 {
		t.Fatalf("unexpected fixed fields: %+v", h)
	}
	if !h.QR || h.Opcode != 15 || !h.AA || !h.TC || !h.RD || !h.RA || h.RCode != 15 {
		t.Fatalf("unexpected decoded flags: %+v", h)
	}
}

func TestBuildHeader(t *testing.T) {
	wire := make([]byte, 12)
	if got := BuildHeader(wire, 0x1234, 0x8180, 1, 2, 3, 4); got != 12 {
		t.Fatalf("BuildHeader returned %d, want 12", got)
	}
	want := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 3, 0, 4}
	for i := range want {
		if wire[i] != want[i] {
			t.Fatalf("wire[%d] = %#x, want %#x", i, wire[i], want[i])
		}
	}
}

func TestParseHeaderBatch(t *testing.T) {
	const (
		batchSize = 4
		stride    = 64
	)
	buffer := make([]byte, batchSize*stride)
	lengths := make([]uint16, batchSize)
	for i := range lengths {
		copy(buffer[i*stride:], sampleQuery)
		lengths[i] = uint16(len(sampleQuery))
		binary.BigEndian.PutUint16(buffer[i*stride:], uint16(i+1))
	}
	lengths[2] = 2

	headers := make([]Header, batchSize)
	statuses := make([]error, batchSize)
	parsed, err := ParseHeadersStrided(buffer, stride, lengths, headers, statuses)
	if err != nil {
		t.Fatalf("ParseStrided failed: %v", err)
	}
	if parsed != batchSize-1 {
		t.Fatalf("parsed = %d, want %d", parsed, batchSize-1)
	}
	for i := range headers {
		if i == 2 {
			if statuses[i] != ErrShort {
				t.Fatalf("status[%d] = %v, want ErrShort", i, statuses[i])
			}
			continue
		}
		if statuses[i] != nil {
			t.Fatalf("status[%d] = %v, want nil", i, statuses[i])
		}
		if headers[i].ID != uint16(i+1) {
			t.Fatalf("header[%d].ID = %d, want %d", i, headers[i].ID, i+1)
		}
	}
}

func TestParseHeaderBatchValidation(t *testing.T) {
	buffer := make([]byte, 64)
	headers := make([]Header, 1)
	statuses := make([]error, 1)

	tests := []struct {
		name    string
		buffer  []byte
		stride  int
		lengths []uint16
		out     []Header
		status  []error
	}{
		{name: "short stride", buffer: buffer, stride: 11, lengths: []uint16{11}, out: headers, status: statuses},
		{name: "short output", buffer: buffer, stride: 64, lengths: []uint16{12}, status: statuses},
		{name: "short status", buffer: buffer, stride: 64, lengths: []uint16{12}, out: headers},
		{name: "short buffer", buffer: buffer[:63], stride: 64, lengths: []uint16{12}, out: headers, status: statuses},
		{name: "length exceeds stride", buffer: buffer, stride: 64, lengths: []uint16{65}, out: headers, status: statuses},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseHeadersStrided(tt.buffer, tt.stride, tt.lengths, tt.out, tt.status); err == nil {
				t.Fatal("ParseHeadersStrided unexpectedly succeeded")
			}
		})
	}
}

func BenchmarkParseHeader(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseHeader(sampleQuery)
	}
}

func BenchmarkParseHeaderGoScalar(b *testing.B) {
	var header Header
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ParseHeaderInto(sampleQuery, &header)
	}
	benchmarkHeader = header
}

func BenchmarkParseHeaderASM(b *testing.B) {
	var header Header
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = parseHeaderASMInto(sampleQuery, &header)
	}
	benchmarkHeader = header
}

func BenchmarkParseQuestion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseQuestion(sampleQuery, 12)
	}
}

func BenchmarkParsePacket(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseHeader(sampleQuery)
		_, _, _ = ParseQuestion(sampleQuery, 12)
	}
}

func BenchmarkParseHeaderBatch64(b *testing.B) {
	const (
		batchSize = 64
		stride    = 64
	)
	buffer := make([]byte, batchSize*stride)
	lengths := make([]uint16, batchSize)
	for i := range lengths {
		copy(buffer[i*stride:], sampleQuery)
		lengths[i] = uint16(len(sampleQuery))
	}
	headers := make([]Header, batchSize)
	statuses := make([]error, batchSize)
	b.ReportAllocs()
	b.SetBytes(int64(batchSize * len(sampleQuery)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseHeadersStrided(buffer, stride, lengths, headers, statuses)
	}
}
