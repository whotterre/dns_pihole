package main

import (
	"log"
	"net"
	"net/http"
)

func main() {
	// Listen on localhost UDP port 5356
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 53,
	})
	if err != nil {
		log.Fatal("Failed to listen:", err)
	}
	defer conn.Close()

	log.Println("DNS Server started on port 5356")

	if err := LoadBlocklist("./lists/global_hagezi.txt"); err != nil {
		log.Printf("Warning: %v", err)
	}
	go func() {
		// Start HTTP server here
		app := http.NewServeMux()
		SetupRoutes(app)
		err = http.ListenAndServe(":8000", app)
		if err != nil {
			log.Fatalf("HTTP server crashed: %v", err)
		}
	}()

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
		if !isBlocked {
			// Open a temporary connection to an upstream DNS server
			upstreamConn, err := net.Dial("udp", "1.1.1.1:53")
			if err != nil {
				log.Printf("Failed to dial upstream: %v", err)
				continue
			}

			// Forward the exact raw buffer we received from the client
			_, err = upstreamConn.Write(buffer[:n])
			if err != nil {
				log.Printf("Failed to forward upstream: %v", err)
				upstreamConn.Close()
				continue
			}

			// Read the upstream response
			upstreamResponse := make([]byte, 512)
			respN, err := upstreamConn.Read(upstreamResponse)
			upstreamConn.Close()
			if err != nil {
				log.Printf("Failed to read from upstream: %v", err)
				continue
			}

			// Send the authentic response straight back to your client
			_, err = conn.WriteToUDP(upstreamResponse[:respN], addr)
			if err != nil {
				log.Printf("Failed sending upstream response to client: %v", err)
			}
		} else {
			// Call your existing BuildDNSResponse for blocks
			response := BuildDNSResponse(header, buffer[:n], domain, qtype, true)
			conn.WriteToUDP(response, addr)
		}
	}
}
