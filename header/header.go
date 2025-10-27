package header

import (
	"encoding/binary"
	"fmt"
)

type DNSHeader struct {
	ID       uint16 // Packet identifier
	Flags    uint16 // QR, Opcode, AA, TC, RD, RA, Z, RCODE
	QDCount  uint16 // Question Count
	ANCount  uint16 // Answer Record Count
	NSCount  uint16 // Authority Record Count
	AddCount uint16 // Additional Record Count
}

const (
	FlagQR     = 0x8000 // Bit 15: Query/Response
	FlagOpcode = 0x7800 // Bits 11-14: Operation Code
	FlagAA     = 0x0400 // Bit 10: Authoritative Answer
	FlagTC     = 0x0200 // Bit 9: Truncation
	FlagRD     = 0x0100 // Bit 8: Recursion Desired
	FlagRA     = 0x0080 // Bit 7: Recursion Available
	FlagZ      = 0x0070 // Bits 4-6: Reserved (Z)
	FlagRcode  = 0x000F // Bits 0-3: Response Code
)

// GetQR extracts the QR flag (1 bit)
func (h *DNSHeader) GetQR() uint16 {
	return (h.Flags & FlagQR) >> 15
}

// GetOpcode extracts the OPCODE field (4 bits)
func (h *DNSHeader) GetOpcode() uint16 {
	return (h.Flags & FlagOpcode) >> 11
}

// GetRD extracts the RD flag (1 bit)
func (h *DNSHeader) GetRD() uint16 {
	return (h.Flags & FlagRD) >> 8
}

func (h *DNSHeader) GetRcode() uint16 {
	return h.Flags & FlagRcode
}

func CreateResponseHeader(request *DNSHeader) *DNSHeader {
	opcode := request.GetOpcode()
	rd := request.GetRD()

	rcode := uint16(0) // No error
	if opcode != 0 {
		rcode = 4 // Not Implemented
	}

	// build response flags
	// Set QR to 1 (response)
	// Set AA to 0 (not authoritative)
	// Set OPCODE to mimic
	// set TC to 0 (not truncated)
	// Set RA to 0
	// Set Z to 0
	// RCODE is calculated
	responseFlags := uint16(1<<15) | (opcode << 11) | (rd << 8) | (rcode & 0x0F)

	return &DNSHeader{
		ID:       request.ID,
		Flags:    responseFlags,
		QDCount:  0, // Will be set by the caller
		ANCount:  0, // Will be set by the caller
		NSCount:  0, // Will be set by the caller
		AddCount: 0, // Will be set by the caller
	}
}

// Return a new header with the default values set
func NewDNSHeader(id uint16) *DNSHeader {
	return &DNSHeader{
		ID:       id,
		Flags:    0x8000,
		QDCount:  0,
		ANCount:  0,
		NSCount:  0,
		AddCount: 0,
	}
}

func ParseDNSHeader(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("data too short to contain DNS header")
	}

	header := &DNSHeader{
		ID:       binary.BigEndian.Uint16(data[0:2]),
		Flags:    binary.BigEndian.Uint16(data[2:4]),
		QDCount:  binary.BigEndian.Uint16(data[4:6]),
		ANCount:  binary.BigEndian.Uint16(data[6:8]),
		NSCount:  binary.BigEndian.Uint16(data[8:10]),
		AddCount: binary.BigEndian.Uint16(data[10:12]),
	}

	return header, nil
}

// serialize the DNSHeader to 12 bytes slice
func (h *DNSHeader) ToBytes() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	binary.BigEndian.PutUint16(buf[2:4], h.Flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.AddCount)
	return buf
}
