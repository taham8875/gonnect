package message

import "gonnect/header"

type DNSMessage struct {
	Header header.DNSHeader
	// Other fields like Questions, Answers, etc. can be added here later
}

func ParseDNSMessage(data []byte) (*DNSMessage, error) {
	header, err := header.ParseDNSHeader(data)
	if err != nil {
		return nil, err
	}

	dnsMessage := &DNSMessage{
		Header: *header,
	}

	return dnsMessage, nil
}

func NewResponse(request *DNSMessage) *DNSMessage {
	responseHeader := header.NewDNSHeader(request.Header.ID)
	// Set QR flag to 1 (response)
	responseHeader.Flags |= 0x8000
	// Set other flags as needed for a response

	return &DNSMessage{
		Header: *responseHeader,
	}
}

func (msg *DNSMessage) ToBytes() []byte {
	headerBytes := msg.Header.ToBytes()

	return headerBytes
}
