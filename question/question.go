package question

import (
	"encoding/binary"
	"fmt"
)

type DNSQuestion struct {
	Name  []byte // Domain name
	Type  uint16 // Record type (1=A record)
	Class uint16 // Record class (1=IN)
}

func extractName(data []byte, offset int) ([]byte, int, error) {
	if offset >= len(data) {
		return nil, 0, fmt.Errorf("offset out of bounds")
	}

	result := make([]byte, 0)
	visited := make(map[int]bool)
	currentOffset := offset
	readingFromStream := true
	var bytesConsumed int = 0

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
			// DNS pointer format: 11xxxxxx yyyyyyyy (14-bit offset)
			// Take lower 6 bits of first byte and combine with second byte
			pointerOffset := (int(labelLen&0x3F) << 8) | int(data[currentOffset+1])

			// calculate bytes consumed from the stream including the pointer
			// currentOffset is where the pointer starts, so we consume 2 more bytes
			if readingFromStream {
				bytesConsumed = currentOffset + 2 - offset
			}

			// follow the pointer and expand the name
			// Stop reading from stream when following pointers
			readingFromStream = false
			expandedName, _, err := extractName(data, pointerOffset)
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
	}

	// Calculate total bytes consumed if not already set
	if readingFromStream && bytesConsumed == 0 {
		bytesConsumed = currentOffset - offset
	}

	return result, bytesConsumed, nil
}

func ParseDNSQuestion(data []byte, offset int) (*DNSQuestion, int, error) {
	if offset >= len(data) {
		return nil, 0, fmt.Errorf("offset out of bounds")
	}

	name, nameBytes, err := extractName(data, offset)
	if err != nil {
		return nil, 0, err
	}

	typeOffset := offset + nameBytes

	if typeOffset+4 > len(data) {
		return nil, 0, fmt.Errorf("not enough data for type and class")
	}

	qType := binary.BigEndian.Uint16(data[typeOffset : typeOffset+2])
	qClass := binary.BigEndian.Uint16(data[typeOffset+2 : typeOffset+4])

	question := &DNSQuestion{
		Name:  name,
		Type:  qType,
		Class: qClass,
	}

	return question, nameBytes + 4, nil
}

func (q *DNSQuestion) ToBytes() []byte {
	buf := make([]byte, 0, len(q.Name)+4)

	buf = append(buf, q.Name...)

	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, q.Type)
	buf = append(buf, typeBytes...)

	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, q.Class)
	buf = append(buf, classBytes...)

	return buf
}
