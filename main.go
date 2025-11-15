package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
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

	if err := loadBlocklist("blocklist.txt"); err != nil {
		log.Printf("Warning: %v", err)
	}

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

// This reads data and converts it from bytes to big-endian format and the data is seperated
func parseDNSHeader(data []byte) entities.DNSHeader {
	if len(data) < 12 {
		return entities.DNSHeader{}
	}
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
	return parseDomainNameHelper(data, offset, make(map[int]bool))
}

func parseDomainNameHelper(data []byte, offset int, visited map[int]bool) (string, int) {
	var name string

	for {
		if offset >= len(data) {
			break
		}

		if visited[offset] {
			break
		}
		visited[offset] = true

		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}

		// Handle DNS compression pointers (0xC0)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			// Pointer to another location (14-bit offset)
			pointer := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			if pointer >= len(data) {
				break
			}
			suffix, _ := parseDomainNameHelper(data, pointer, visited)
			if len(suffix) > 0 {
				if len(name) > 0 {
					name += "."
				}
				name += suffix
			}
			offset += 2
			break
		}

		if length > 63 {
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

func buildDNSResponse(headerData entities.DNSHeader, query []byte, domain string, qtype uint16) []byte {
	response := make([]byte, 512)
	offset := 0

	canAnswer := qtype == 1

	// Build the DNS header
	response[0] = byte(headerData.ID >> 8)

	response[1] = byte(headerData.ID)

	response[2] = 0x81 // Sets Query flag to 1 (Response) and RD flag to 1

	if canAnswer {
		response[3] = 0x80 // RA=1, RCODE=0 (no error)
	} else {
		response[3] = 0x80 // RA=1, RCODE=0 (we'll return empty answer)
		log.Printf("Cannot answer query type %d for %s", qtype, domain)
	}
	response[4] = 0x00 // QDCOUNT high
	response[5] = 0x01 // QDCount low
	response[6] = 0x00 //ANCount high
	if canAnswer {
		response[7] = 0x01 // ANCOUNT low (1 answer)
	} else {
		response[7] = 0x00 // ANCOUNT low (0 answers)
	}
	response[8] = 0x00  // NSCOUNT high
	response[9] = 0x00  // NSCOUNT low
	response[10] = 0x00 // ARCOUNT high
	response[11] = 0x00 // ARCOUNT low
	offset = 12

	// Copy question section from original query
	questionEnd := 12
	for questionEnd < len(query) && query[questionEnd] != 0 {
		length := int(query[questionEnd])
		if length&0xC0 == 0xC0 {
			questionEnd += 2
			break
		}

		questionEnd += 1 + length
	}
	if questionEnd < len(query) && query[questionEnd] == 0 {
		questionEnd++
	}
	questionEnd += 4 // Skip QTYPE (2 bytes) + QCLASS (2 bytes)

	// Copy the question section
	if questionEnd <= len(query) {
		questionLen := questionEnd - 12
		copy(response[offset:], query[12:questionEnd])
		offset += questionLen
	}

	// 3. Add Answer Section (only if we can answer)
	if !canAnswer {
		return response[:offset]
	}
	response[offset] = 0xC0
	response[offset+1] = 0x0C
	offset += 2

	// TYPE (A record = 1)
	response[offset] = 0x00
	response[offset+1] = 0x01
	offset += 2

	// CLASS (IN = 1)
	response[offset] = 0x00
	response[offset+1] = 0x01
	offset += 2

	// TTL (300 seconds = 0x0000012C)
	response[offset] = 0x00
	response[offset+1] = 0x00
	response[offset+2] = 0x01
	response[offset+3] = 0x2C
	offset += 4

	// RDLENGTH (4 bytes for IPv4)
	response[offset] = 0x00
	response[offset+1] = 0x04
	offset += 2

	// RDATA (IP address)
	var ip [4]byte
	if checkIsBlocked(domain) {
		ip = [4]byte{0, 0, 0, 0}
		log.Printf("Blocked: %s", domain)
	} else {
		ip = [4]byte{192, 168, 1, 1}
	}
	response[offset] = ip[0]
	response[offset+1] = ip[1]
	response[offset+2] = ip[2]
	response[offset+3] = ip[3]
	offset += 4

	return response[:offset]
}

var blocklist map[string]bool

func loadBlocklist(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open blocklist: %w", err)
	}
	defer file.Close()

	blocklist = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blocklist[line] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocklist: %w", err)
	}

	log.Printf("Loaded %d blocked domains", len(blocklist))
	return nil
}

func checkIsBlocked(domain string) bool {
	return blocklist[domain]
}
