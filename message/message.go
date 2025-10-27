package message

import (
	"fmt"
	"gonnect/answer"
	"gonnect/header"
	"gonnect/question"
	"net"
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
		Answer:   make([]answer.DNSResourceRecord, 0),
	}

	// parse the question
	// start after the header
	offset := 12
	for i := 0; i < int(header.QDCount); i++ {
		question, bytesRead, err := question.ParseDNSQuestion(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse question %d at offset %d: %w", i, offset, err)
		}
		dnsMessage.Question = append(dnsMessage.Question, *question)
		offset += bytesRead
	}

	// parse the answer section
	for i := 0; i < int(header.ANCount); i++ {
		answer, bytesRead, err := answer.ParseDNSResourceRecord(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse answer %d at offset %d: %w", i, offset, err)
		}
		dnsMessage.Answer = append(dnsMessage.Answer, *answer)
		offset += bytesRead
	}

	return dnsMessage, nil
}

func NewResponse(request *DNSMessage) *DNSMessage {
	responseHeader := header.CreateResponseHeader(&request.Header)

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

func ForwardRequest(request *DNSMessage, resolverAddr string) (*DNSMessage, error) {
	// if there is one question forward it directly
	if len(request.Question) == 1 {
		return forwardOneQuestion(request, resolverAddr)
	}

	// if not, split into multiple requests and merge
	return forwardMultipleQuestions(request, resolverAddr)
}

func forwardOneQuestion(request *DNSMessage, resolverAddr string) (*DNSMessage, error) {
	queryHeader := &header.DNSHeader{
		ID:       request.Header.ID,
		Flags:    0x0100, // RD=1, QR=0
		QDCount:  1,
		ANCount:  0,
		NSCount:  0,
		AddCount: 0,
	}

	query := &DNSMessage{
		Header:   *queryHeader,
		Question: []question.DNSQuestion{request.Question[0]},
		Answer:   []answer.DNSResourceRecord{},
	}

	queryBytes := query.ToBytes()

	// forward the query to the resolver
	resolverConnection, err := net.Dial("udp", resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %w", err)
	}

	defer resolverConnection.Close()

	// send the request
	_, err = resolverConnection.Write(queryBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send query to resolver: %w", err)
	}

	// read the response
	responseBuf := make([]byte, 512)
	size, err := resolverConnection.Read(responseBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from resolver: %w", err)
	}

	response, err := ParseDNSMessage(responseBuf[:size])
	if err != nil {
		return nil, fmt.Errorf("failed to parse response from resolver: %w", err)
	}

	responseHeader := header.CreateResponseHeader(&request.Header)
	responseHeader.QDCount = request.Header.QDCount
	responseHeader.ANCount = response.Header.ANCount

	questions := make([]question.DNSQuestion, len(request.Question))

	copy(questions, request.Question)

	return &DNSMessage{
		Header:   *responseHeader,
		Question: questions,
		Answer:   response.Answer,
	}, nil
}

func forwardMultipleQuestions(request *DNSMessage, resolverAddr string) (*DNSMessage, error) {
	var allAnswers []answer.DNSResourceRecord

	for _, q := range request.Question {
		singleRequest := &DNSMessage{
			Header:   request.Header,
			Question: []question.DNSQuestion{q},
			Answer:   []answer.DNSResourceRecord{},
		}

		response, err := forwardOneQuestion(singleRequest, resolverAddr)
		if err != nil {
			return nil, err
		}

		allAnswers = append(allAnswers, response.Answer...)
	}

	// create the merged  response
	responseHeader := header.CreateResponseHeader(&request.Header)
	responseHeader.QDCount = request.Header.QDCount
	responseHeader.ANCount = uint16(len(allAnswers))

	questions := make([]question.DNSQuestion, len(request.Question))
	copy(questions, request.Question)

	return &DNSMessage{
		Header:   *responseHeader,
		Question: questions,
		Answer:   allAnswers,
	}, nil
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
