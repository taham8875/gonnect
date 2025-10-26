package main

import (
	"fmt"
	"gonnect/message"
	"net"
)

const DNS_PORT = 2053

func main() {
	// TODO: Uncomment the code below to pass the first stage
	//
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", DNS_PORT))
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	fmt.Printf("Listening for DNS queries on %s\n", udpAddr.String())

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		request, err := message.ParseDNSMessage(buf[:size])
		if err != nil {
			fmt.Println("Failed to parse DNS message:", err)
			continue
		}

		response := message.NewResponse(request)

		responseBytes := response.ToBytes()

		_, err = udpConn.WriteToUDP(responseBytes, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
