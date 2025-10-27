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
		return nil, 0, fmt.Errorf("offset out of bounds")
	}

	startOffset := offset

	// Parse name with compression support
	result := make([]byte, 0)
	visited := make(map[int]bool)
	readingFromStream := true
	var bytesConsumed int = 0
	currentOffset := offset

	for {
		if currentOffset >= len(data) {
			return nil, bytesConsumed, fmt.Errorf("offset out of bounds while parsing name")
		}

		// check for infinite loops
		if visited[currentOffset] {
			return nil, bytesConsumed, fmt.Errorf("infinite loop detected while parsing name")
		}
		visited[currentOffset] = true

		labelLen := int(data[currentOffset])

		// check if it is a pointer therefore compression
		if (labelLen & 0xC0) == 0xC0 {
			if currentOffset+1 >= len(data) {
				return nil, bytesConsumed, fmt.Errorf("incomplete pointer")
			}

			// extract the offset from the pointer
			pointerOffset := (int(labelLen&0x3F) << 8) | int(data[currentOffset+1])

			// calculate bytes consumed from the stream including the pointer
			if readingFromStream {
				bytesConsumed = currentOffset + 2 - offset
			}

			// follow the pointer and expand the name
			readingFromStream = false
			expandedName, _, err := extractNameFromAnswer(data, pointerOffset)
			if err != nil {
				return nil, bytesConsumed, err
			}

			result = append(result, expandedName...)
			break
		}

		// not a pointer, regular label
		if labelLen == 0 {
			// end of the name
			result = append(result, 0)
			currentOffset++
			if readingFromStream {
				bytesConsumed = currentOffset - offset
			}
			break
		}

		// check bounds for regular labels
		if labelLen > 63 {
			return nil, bytesConsumed, fmt.Errorf("label length %d exceeds max 63", labelLen)
		}
		if currentOffset+labelLen+1 > len(data) {
			return nil, bytesConsumed, fmt.Errorf("label length %d exceeds data length at offset %d", labelLen, currentOffset)
		}

		// Add this label to result
		result = append(result, data[currentOffset:currentOffset+labelLen+1]...)
		currentOffset += labelLen + 1

		if bytesConsumed == 0 && readingFromStream {
			bytesConsumed = currentOffset - offset
		}
	}

	name := result
	if bytesConsumed == 0 && readingFromStream {
		bytesConsumed = currentOffset - offset
	}
	offset = startOffset + bytesConsumed

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

func extractNameFromAnswer(data []byte, offset int) ([]byte, int, error) {
	result := make([]byte, 0)
	visited := make(map[int]bool)
	currentOffset := offset

	for {
		if currentOffset >= len(data) {
			return nil, 0, fmt.Errorf("offset out of bounds while parsing name")
		}

		if visited[currentOffset] {
			return nil, 0, fmt.Errorf("infinite loop detected")
		}
		visited[currentOffset] = true

		labelLen := int(data[currentOffset])

		if (labelLen & 0xC0) == 0xC0 {
			if currentOffset+1 >= len(data) {
				return nil, 0, fmt.Errorf("incomplete pointer")
			}
			pointerOffset := (int(labelLen&0x3F) << 8) | int(data[currentOffset+1])
			expandedName, _, err := extractNameFromAnswer(data, pointerOffset)
			if err != nil {
				return nil, 0, err
			}
			result = append(result, expandedName...)
			break
		}

		if labelLen == 0 {
			result = append(result, 0)
			currentOffset++
			break
		}

		if labelLen > 63 {
			return nil, 0, fmt.Errorf("label length exceeds max")
		}
		if currentOffset+labelLen+1 > len(data) {
			return nil, 0, fmt.Errorf("label exceeds data length")
		}

		result = append(result, data[currentOffset:currentOffset+labelLen+1]...)
		currentOffset += labelLen + 1
	}

	return result, 0, nil
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
