package main

import (
	"log"
	"net"

	entities "github.com/whotterre/dns_pihole/models"
)

func main() {
	// Listen on UDP port 5354
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 5355,
	})
	if err != nil {
		log.Fatal("Failed to listen:", err)
	}
	defer conn.Close()

	log.Println("DNS Server started on port 5354")

	// Keep the server running
	buffer := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading:", err)
			continue
		}
		log.Printf("Received %d bytes from %s", n, addr)
		log.Printf("First few bytes: %x", buffer[:min(n, 16)])
	}

	// Parse the DNS packet
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DNS headers reads data in big-endian format and the data is seperated
// This part joins them together
func parseDNSHeader(data []byte) entities.DNSHeader {
	return entities.DNSHeader{
		ID:      uint16(data[0]) <<8 | uint16(data[1]),
		Flags:   uint16(data[2]) <<8 | uint16(data[3]),
		QdCount: uint16(data[4]) <<8 | uint16(data[5]),
		AnCount: uint16(data[6]) <<8 | uint16(data[7]),
		NsCount: uint16(data[8]) <<8 | uint16(data[9]),
		ArCount: uint16(data[10]) <<8 | uint16(data[11]),
	}
}

/*
 DNS name data is usually in this form:
 - [length][chars][length][chars][0]
 - eg for google.com, we'd have [6]google[3]com[0]
 This function changes it to the form of google.com
 */
func parseDomainName(data []byte, offset int) (string, int) {
	var name string
	for {
		length := int(data[offset])
		if length == 0 {
			break
		}
		offset++

		name += string(data[offset: offset + length]) + "."

		offset += length
	}
	return name, offset
}

