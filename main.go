package main

import (
	"log"
	"net"
)

func main() {
	// Listen on localhost UDP port 5356
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 5356,
	})
	if err != nil {
		log.Fatal("Failed to listen:", err)
	}
	defer conn.Close()

	log.Println("DNS Server started on port 5356")

	if err := LoadBlocklist("blocklist.txt"); err != nil {
		log.Printf("Warning: %v", err)
	}

	buffer := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading:", err)
			continue
		}
		log.Printf("Received %d bytes from %s", n, addr)
		log.Printf("Query (hex): %x", buffer[:n])

		if n < 12 {
			log.Printf("Query too short (< 12 bytes)")
			continue
		}

		header := ParseDNSHeader(buffer)
		log.Printf("Header - ID: %d, Flags: 0x%04x, Questions: %d", header.ID, header.Flags, header.QdCount)

		domain, endOffset := ParseDomainName(buffer, 12)
		log.Printf("Domain: '%s' (name ends at offset %d)", domain, endOffset)

		// Parse query type and class
		var qtype, qclass uint16
		if endOffset+4 <= n {
			qtype = uint16(buffer[endOffset])<<8 | uint16(buffer[endOffset+1])
			qclass = uint16(buffer[endOffset+2])<<8 | uint16(buffer[endOffset+3])
		}

		qtypeStr := "UNKNOWN"
		switch qtype {
		case 1:
			qtypeStr = "A"
		case 28:
			qtypeStr = "AAAA"
		case 5:
			qtypeStr = "CNAME"
		case 15:
			qtypeStr = "MX"
		}

		log.Printf("Query Type: %s (%d), Class: %d", qtypeStr, qtype, qclass)

		isBlocked := IsBlocked(domain)
		response := BuildDNSResponse(header, buffer[:n], domain, qtype, isBlocked)
		log.Printf("Response built: %d bytes", len(response))
		log.Printf("Response (hex): %x", response)

		written, err := conn.WriteToUDP(response, addr)
		if err != nil {
			log.Printf("Failed to send response: %v", err)
		} else {
			log.Printf("Sent %d bytes back to client", written)
		}
	}
}
