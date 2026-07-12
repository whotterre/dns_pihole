package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
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

	entries, err := os.ReadDir("./lists")
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				if err := LoadBlocklist("./lists/" + entry.Name()); err != nil {
					log.Printf("Warning loading %s: %v", entry.Name(), err)
				} else {
					log.Printf("Loaded blocklist: %s", entry.Name())
				}
			}
		}
	} else {
		log.Printf("Failed to read lists directory: %v", err)
	}
	cleanupStaleEntries()

	go func() {
		// Start HTTP server here
		app := http.NewServeMux()
		SetupRoutes(app)
		log.Println("Started HTTP server on port 8000")
		err := http.ListenAndServe(":8000", app)
		if err != nil {
			log.Fatalf("HTTP server crashed: %v", err)
		}
	}()

	for {
		buffer := make([]byte, 4096)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading:", err)
			continue
		}

		go func(reqBuffer []byte, clientAddr *net.UDPAddr) {
			atomic.AddUint64(&TotalQueries, 1)

			log.Printf("Received %d bytes from %s", len(reqBuffer), clientAddr)
			log.Printf("Query (hex): %x", reqBuffer)

			if len(reqBuffer) < 12 {
				log.Printf("Query too short (< 12 bytes)")
				return
			}

			header := ParseDNSHeader(reqBuffer)
			log.Printf("Header - ID: %d, Flags: 0x%04x, Questions: %d", header.ID, header.Flags, header.QdCount)

			domain, endOffset := ParseDomainName(reqBuffer, 12)
			log.Printf("Domain: '%s' (name ends at offset %d)", domain, endOffset)

			// Parse query type and class
			var qtype, qclass uint16
			if endOffset+4 <= len(reqBuffer) {
				qtype = uint16(reqBuffer[endOffset])<<8 | uint16(reqBuffer[endOffset+1])
				qclass = uint16(reqBuffer[endOffset+2])<<8 | uint16(reqBuffer[endOffset+3])
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
					return
				}
				defer upstreamConn.Close()

				// Forward the exact raw buffer we received from the client
				_, err = upstreamConn.Write(reqBuffer)
				if err != nil {
					log.Printf("Failed to forward upstream: %v", err)
					return
				}

				// Set deadline BEFORE reading to prevent hanging
				upstreamConn.SetReadDeadline(time.Now().Add(2 * time.Second))

				// Read the upstream response
				upstreamResponse := make([]byte, 4096)
				respN, err := upstreamConn.Read(upstreamResponse)
				if err != nil {
					log.Printf("Failed to read from upstream: %v", err)
					return
				}

				// Send the authentic response straight back to your client
				_, err = conn.WriteToUDP(upstreamResponse[:respN], clientAddr)
				if err != nil {
					log.Printf("Failed sending upstream response to client: %v", err)
				}
			} else {
				atomic.AddUint64(&BlockedQueries, 1)
				// Call your existing BuildDNSResponse for blocks
				response := BuildDNSResponse(header, reqBuffer, domain, qtype, true)
				conn.WriteToUDP(response, clientAddr)
			}
		}(buffer[:n], addr)
	}
}
