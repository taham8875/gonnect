package answer

import (
	"encoding/binary"
	"fmt"
)

type DNSResourceRecord struct {
	Name     []byte // Domain name
	Type     uint16 // Record type (1=A record)
	Class    uint16 // Record class (1=IN)
	TTL      uint32 // Time to live
	RDLength uint16 // Length of RData
	RData    []byte // Resource data
}

func NewARecord(name []byte, ipAddr [4]byte, ttl uint32) *DNSResourceRecord {
	return &DNSResourceRecord{
		Name:     name,
		Type:     1, // A record
		Class:    1, // IN class
		TTL:      ttl,
		RDLength: uint16(len(ipAddr)),
		RData:    ipAddr[:],
	}
}

func ParseDNSResourceRecord(data []byte, offset int) (*DNSResourceRecord, int, error) {
	if offset >= len(data) {
		return nil, offset, fmt.Errorf("offset out of bounds")
	}

	startOffset := offset
	offsetCopy := offset

	for {
		if offsetCopy >= len(data) {
			return nil, offset, fmt.Errorf("offset out of bounds while parsing name")
		}

		labelLen := int(data[offset])

		if labelLen == 0 {
			// end of the name
			offsetCopy++
			break
		}

		if offsetCopy+labelLen+1 > len(data) {
			return nil, offset, fmt.Errorf("label length exceeds data length")
		}

		offsetCopy += labelLen + 1
	}

	name := data[startOffset:offsetCopy]
	offset = offsetCopy

	if offset+10 > len(data) {
		return nil, offset, fmt.Errorf("not enough data for resource record fields")
	}

	rType := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	rClass := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	ttl := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	rdLength := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(rdLength) > len(data) {
		return nil, offset, fmt.Errorf("RData length exceeds data length")
	}

	rData := data[offset : offset+int(rdLength)]
	offset += int(rdLength)

	resourceRecord := &DNSResourceRecord{
		Name:     name,
		Type:     rType,
		Class:    rClass,
		TTL:      ttl,
		RDLength: rdLength,
		RData:    rData,
	}

	return resourceRecord, offset - startOffset, nil
}

func (rr *DNSResourceRecord) ToBytes() []byte {
	buf := make([]byte, 0, len(rr.Name)+10+len(rr.RData))

	buf = append(buf, rr.Name...)
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, rr.Type)
	buf = append(buf, typeBytes...)

	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, rr.Class)
	buf = append(buf, classBytes...)

	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, rr.TTL)
	buf = append(buf, ttlBytes...)

	rdLengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLengthBytes, rr.RDLength)
	buf = append(buf, rdLengthBytes...)

	buf = append(buf, rr.RData...)

	return buf
}
