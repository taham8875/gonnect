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

func ParseDNSQuestion(data []byte, offset int) (*DNSQuestion, int, error) {
	if offset >= len(data) {
		return nil, offset, fmt.Errorf("offset out of bounds")
	}

	startOffset := offset

	for {
		if offset >= len(data) {
			return nil, offset, fmt.Errorf("offset out of bounds while parsing name")
		}

		labelLen := int(data[offset])

		if labelLen == 0 {
			// end of the name
			offset++
			break
		}

		if offset+labelLen+1 > len(data) {
			return nil, offset, fmt.Errorf("label length exceeds data length")
		}

		offset += labelLen + 1
	}

	name := data[startOffset:offset]

	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("not enough data for type and class")
	}

	qType := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	qClass := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	question := &DNSQuestion{
		Name:  name,
		Type:  qType,
		Class: qClass,
	}

	return question, offset - startOffset, nil
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
