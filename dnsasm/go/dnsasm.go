// Package dnsasm provides Go bindings for the ultra-fast DNSASM DNS packet processor.
//
// DNSASM is written in hand-optimized assembly (x86_64 SSE2 / ARM64 NEON) and
// achieves parsing rates of 100+ million headers per second.
//
// Example usage:
//
//	packet := []byte{...} // Raw DNS packet
//	header, err := dnsasm.ParseHeader(packet)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("ID: %d, QR: %v\n", header.ID, header.QR)
package dnsasm

/*
#cgo CFLAGS: -I${SRCDIR}/../include -O3
#cgo LDFLAGS: -L${SRCDIR}/../build/lib -ldnsasm

#include "dnsasm.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

// Error codes
var (
	ErrShort    = errors.New("dnsasm: packet too short")
	ErrName     = errors.New("dnsasm: invalid name format")
	ErrPointer  = errors.New("dnsasm: invalid compression pointer")
	ErrLoop     = errors.New("dnsasm: compression pointer loop")
	ErrOverflow = errors.New("dnsasm: name too long")
)

// errorFromCode converts a C error code to a Go error.
func errorFromCode(code C.int) error {
	switch code {
	case C.DNSASM_OK:
		return nil
	case C.DNSASM_ERR_SHORT:
		return ErrShort
	case C.DNSASM_ERR_NAME:
		return ErrName
	case C.DNSASM_ERR_POINTER:
		return ErrPointer
	case C.DNSASM_ERR_LOOP:
		return ErrLoop
	case C.DNSASM_ERR_OVERFLOW:
		return ErrOverflow
	default:
		return errors.New("dnsasm: unknown error")
	}
}

// Header represents a parsed DNS header.
type Header struct {
	ID      uint16 // Transaction ID
	Flags   uint16 // Raw flags field
	QDCount uint16 // Question count
	ANCount uint16 // Answer count
	NSCount uint16 // Authority count
	ARCount uint16 // Additional count

	// Parsed flags
	QR     bool  // Query (false) or Response (true)
	Opcode uint8 // Operation code
	AA     bool  // Authoritative Answer
	TC     bool  // Truncated
	RD     bool  // Recursion Desired
	RA     bool  // Recursion Available
	RCode  uint8 // Response code
}

// parseHeaderASMInto is retained as a benchmark control for the optional native
// implementation. Production header rejection uses ParseHeaderInto because the
// cgo transition costs more than parsing twelve bytes in Go.
func parseHeaderASMInto(packet []byte, header *Header) error {
	if len(packet) < 12 {
		return ErrShort
	}

	var ch C.dnsasm_header_t
	if status := C.dnsasm_parse_header(
		(*C.uint8_t)(unsafe.Pointer(&packet[0])),
		C.size_t(len(packet)),
		&ch,
	); status != C.DNSASM_OK {
		return errorFromCode(status)
	}

	*header = Header{
		ID:      uint16(ch.id),
		Flags:   uint16(ch.flags),
		QDCount: uint16(ch.qdcount),
		ANCount: uint16(ch.ancount),
		NSCount: uint16(ch.nscount),
		ARCount: uint16(ch.arcount),
		QR:      ch.qr != 0,
		Opcode:  uint8(ch.opcode),
		AA:      ch.aa != 0,
		TC:      ch.tc != 0,
		RD:      ch.rd != 0,
		RA:      ch.ra != 0,
		RCode:   uint8(ch.rcode),
	}
	return nil
}

// ParseHeadersStrided parses fixed-stride packet slots such as buffers prepared
// for recvmmsg. Caller-owned output and status slices keep steady-state parsing
// allocation-free.
func ParseHeadersStrided(buffer []byte, stride int, lengths []uint16, out []Header, statuses []error) (int, error) {
	count := len(lengths)
	if count == 0 {
		return 0, nil
	}
	if stride < 12 {
		return 0, fmt.Errorf("dnsasm: stride %d is smaller than a DNS header", stride)
	}
	if count > len(out) || count > len(statuses) {
		return 0, errors.New("dnsasm: output slices are smaller than the batch")
	}
	if count > len(buffer)/stride {
		return 0, errors.New("dnsasm: buffer is smaller than the fixed-stride batch")
	}
	for _, length := range lengths {
		if int(length) > stride {
			return 0, errors.New("dnsasm: packet length exceeds stride")
		}
	}

	parsed := 0
	for i := 0; i < count; i++ {
		start := i * stride
		statuses[i] = ParseHeaderInto(buffer[start:start+int(lengths[i])], &out[i])
		if statuses[i] == nil {
			parsed++
		} else {
			out[i] = Header{}
		}
	}
	return parsed, nil
}

// Question represents a parsed DNS question.
type Question struct {
	Name    string // Decompressed name (e.g., "www.example.com")
	Type    uint16 // Query type (e.g., 1 for A)
	Class   uint16 // Query class (e.g., 1 for IN)
	WireLen uint16 // Bytes consumed from wire
}

// RR represents a parsed DNS resource record.
type RR struct {
	Name     string // Decompressed name
	Type     uint16 // Record type
	Class    uint16 // Record class
	TTL      uint32 // Time to live
	RDLength uint16 // RDATA length
	RData    []byte // Raw RDATA
	WireLen  uint16 // Bytes consumed from wire
}

// ParseHeaderInto parses a DNS header into caller-owned storage without
// allocations or a cgo transition.
func ParseHeaderInto(packet []byte, header *Header) error {
	if len(packet) < 12 {
		return ErrShort
	}

	header.ID = binary.BigEndian.Uint16(packet[0:2])
	header.Flags = binary.BigEndian.Uint16(packet[2:4])
	header.QDCount = binary.BigEndian.Uint16(packet[4:6])
	header.ANCount = binary.BigEndian.Uint16(packet[6:8])
	header.NSCount = binary.BigEndian.Uint16(packet[8:10])
	header.ARCount = binary.BigEndian.Uint16(packet[10:12])
	header.QR = header.Flags&(1<<15) != 0
	header.Opcode = uint8((header.Flags >> 11) & 0xf)
	header.AA = header.Flags&(1<<10) != 0
	header.TC = header.Flags&(1<<9) != 0
	header.RD = header.Flags&(1<<8) != 0
	header.RA = header.Flags&(1<<7) != 0
	header.RCode = uint8(header.Flags & 0xf)
	return nil
}

// ParseHeader parses the DNS header from a packet.
func ParseHeader(packet []byte) (*Header, error) {
	header := new(Header)
	if err := ParseHeaderInto(packet, header); err != nil {
		return nil, err
	}
	return header, nil
}

// ParseQuestion parses a DNS question section starting at the given offset.
// Returns the parsed question and the new offset after the question.
func ParseQuestion(packet []byte, offset int) (*Question, int, error) {
	if offset >= len(packet) {
		return nil, 0, ErrShort
	}

	var cq C.dnsasm_question_t
	result := C.dnsasm_parse_question(
		(*C.uint8_t)(unsafe.Pointer(&packet[0])),
		C.size_t(len(packet)),
		C.size_t(offset),
		&cq,
	)

	if result.error != C.DNSASM_OK {
		return nil, 0, errorFromCode(result.error)
	}

	// Convert wire-format name to dotted notation
	nameLen := int(cq.name_len)
	nameBytes := make([]byte, nameLen)
	for i := 0; i < nameLen; i++ {
		nameBytes[i] = byte(cq.name[i])
	}
	name := wireNameToString(nameBytes, nameLen)

	return &Question{
		Name:    name,
		Type:    uint16(cq.qtype),
		Class:   uint16(cq.qclass),
		WireLen: uint16(cq.wire_len),
	}, int(result.offset), nil
}

// ParseRR parses a DNS resource record starting at the given offset.
func ParseRR(packet []byte, offset int) (*RR, int, error) {
	if offset >= len(packet) {
		return nil, 0, ErrShort
	}

	var crr C.dnsasm_rr_t
	result := C.dnsasm_parse_rr(
		(*C.uint8_t)(unsafe.Pointer(&packet[0])),
		C.size_t(len(packet)),
		C.size_t(offset),
		&crr,
	)

	if result.error != C.DNSASM_OK {
		return nil, 0, errorFromCode(result.error)
	}

	// Convert wire-format name
	nameLen := int(crr.name_len)
	nameBytes := make([]byte, nameLen)
	for i := 0; i < nameLen; i++ {
		nameBytes[i] = byte(crr.name[i])
	}
	name := wireNameToString(nameBytes, nameLen)

	// Copy RDATA
	rdata := make([]byte, crr.rdlength)
	if crr.rdlength > 0 && crr.rdata != nil {
		copy(rdata, (*[65535]byte)(unsafe.Pointer(crr.rdata))[:crr.rdlength:crr.rdlength])
	}

	return &RR{
		Name:     name,
		Type:     uint16(crr.rtype),
		Class:    uint16(crr.rclass),
		TTL:      uint32(crr.ttl),
		RDLength: uint16(crr.rdlength),
		RData:    rdata,
		WireLen:  uint16(crr.wire_len),
	}, int(result.offset), nil
}

// wireNameToString converts a wire-format DNS name to dotted notation.
// Wire format: len1, label1, len2, label2, ..., 0
// Dotted: label1.label2....
func wireNameToString(wire []byte, length int) string {
	if length == 0 || (length == 1 && wire[0] == 0) {
		return "."
	}

	var result []byte
	pos := 0

	for pos < length && wire[pos] != 0 {
		labelLen := int(wire[pos])
		pos++

		if pos+labelLen > length {
			break
		}

		if len(result) > 0 {
			result = append(result, '.')
		}
		result = append(result, wire[pos:pos+labelLen]...)
		pos += labelLen
	}

	return string(result)
}

// BuildHeader creates a DNS header in wire format.
func BuildHeader(buf []byte, id, flags, qdcount, ancount, nscount, arcount uint16) int {
	if len(buf) < 12 {
		return 0
	}

	n := C.dnsasm_build_header(
		(*C.uint8_t)(unsafe.Pointer(&buf[0])),
		C.uint16_t(id),
		C.uint16_t(flags),
		C.uint16_t(qdcount),
		C.uint16_t(ancount),
		C.uint16_t(nscount),
		C.uint16_t(arcount),
	)

	return int(n)
}

// DNS record types
const (
	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypePTR   = 12
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33
	TypeOPT   = 41
	TypeANY   = 255
)

// DNS classes
const (
	ClassIN  = 1
	ClassCH  = 3
	ClassHS  = 4
	ClassANY = 255
)

// DNS response codes
const (
	RCodeNoError  = 0
	RCodeFormErr  = 1
	RCodeServFail = 2
	RCodeNXDomain = 3
	RCodeNotImp   = 4
	RCodeRefused  = 5
)

// DNS header flags
const (
	FlagQR = 1 << 15 // Query/Response
	FlagAA = 1 << 10 // Authoritative Answer
	FlagTC = 1 << 9  // Truncated
	FlagRD = 1 << 8  // Recursion Desired
	FlagRA = 1 << 7  // Recursion Available
)
