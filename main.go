package main

import (
	"log"
	"net"
	"strings"

	entities "github.com/whotterre/dns_pihole/models"
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

	// Keep the server running
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

		header := parseDNSHeader(buffer)
		log.Printf("Header - ID: %d, Flags: 0x%04x, Questions: %d", header.ID, header.Flags, header.QdCount)

		domain, endOffset := parseDomainName(buffer, 12)
		log.Printf("Domain: '%s' (name ends at offset %d)", domain, endOffset)

		// Parse query type and class
		var qtype, qclass uint16
		if endOffset + 4 <= n {
			qtype = uint16(buffer[endOffset]) << 8 | uint16(buffer[endOffset + 1])
			qclass = uint16(buffer[endOffset + 2]) << 8 | uint16(buffer[endOffset + 3])
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

		response := buildDNSResponse(header, buffer[:n], domain, qtype)
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

// DNS headers reads data in big-endian format and the data is seperated
// This part joins them together
func parseDNSHeader(data []byte) entities.DNSHeader {
	return entities.DNSHeader{
		ID:      uint16(data[0])<<8 | uint16(data[1]),
		Flags:   uint16(data[2])<<8 | uint16(data[3]),
		QdCount: uint16(data[4])<<8 | uint16(data[5]),
		AnCount: uint16(data[6])<<8 | uint16(data[7]),
		NsCount: uint16(data[8])<<8 | uint16(data[9]),
		ArCount: uint16(data[10])<<8 | uint16(data[11]),
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
		if offset >= len(data) {
			break
		}

		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}

		// Handle DNS compression pointers (0xC0)
		if length & 0xC0 == 0xC0 {
			if offset + 1 >= len(data) {
				break
			}
			// Pointer to another location (14-bit offset)
			pointer := int(data[offset] & 0x3F) << 8 | int(data[offset + 1])
			suffix, _ := parseDomainName(data, pointer)
			if len(suffix) > 0 {
				if len(name) > 0 {
					name += "."
				}
				name += suffix
			}
			offset += 2
			break
		}

		offset++
		if offset+length > len(data) {
			break
		}

		if len(name) > 0 {
			name += "."
		}
		name += string(data[offset : offset+length])
		offset += length
	}

	return name, offset
}

