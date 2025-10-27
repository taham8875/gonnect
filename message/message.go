package message

import (
	"gonnect/answer"
	"gonnect/header"
	"gonnect/question"
)

type DNSMessage struct {
	Header   header.DNSHeader
	Question []question.DNSQuestion
	Answer   []answer.DNSResourceRecord
	// Other fields like Questions, Answers, etc. can be added here later
}

func ParseDNSMessage(data []byte) (*DNSMessage, error) {
	header, err := header.ParseDNSHeader(data)
	if err != nil {
		return nil, err
	}

	dnsMessage := &DNSMessage{
		Header:   *header,
		Question: make([]question.DNSQuestion, 0),
	}

	// parse the question
	// start after the header
	offset := 12
	for i := 0; i < int(header.QDCount); i++ {
		question, bytesRead, err := question.ParseDNSQuestion(data, offset)
		if err != nil {
			return nil, err
		}
		dnsMessage.Question = append(dnsMessage.Question, *question)
		offset += bytesRead
	}

	return dnsMessage, nil
}

func NewResponse(request *DNSMessage) *DNSMessage {
	responseHeader := header.NewDNSHeader(request.Header.ID)
	// Set QR flag to 1 (response)
	responseHeader.Flags |= 0x8000

	// set QDCount to match request question count
	responseHeader.QDCount = request.Header.QDCount

	questions := make([]question.DNSQuestion, len(request.Question))
	copy(questions, request.Question)

	answers := make([]answer.DNSResourceRecord, 0)
	for _, q := range questions {
		if q.Type == 1 { // A record request
			// create dummy record with ip 8.8.8.8
			// in real life dns, this would be looked up from a database or external source
			ipAddr := [4]byte{8, 8, 8, 8}
			aRecord := answer.NewARecord(q.Name, ipAddr, 300)
			answers = append(answers, *aRecord)
		}
	}

	// set ANCount to number of answers
	responseHeader.ANCount = uint16(len(answers))

	return &DNSMessage{
		Header:   *responseHeader,
		Question: questions,
		Answer:   answers,
	}
}

func (msg *DNSMessage) ToBytes() []byte {
	headerBytes := msg.Header.ToBytes()

	questionBytes := make([]byte, 0)
	for _, q := range msg.Question {
		questionBytes = append(questionBytes, q.ToBytes()...)
	}

	answerBytes := make([]byte, 0)
	for _, a := range msg.Answer {
		answerBytes = append(answerBytes, a.ToBytes()...)
	}

	messageBytes := append(headerBytes, questionBytes...)
	messageBytes = append(messageBytes, answerBytes...)

	return messageBytes
}
