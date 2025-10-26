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
