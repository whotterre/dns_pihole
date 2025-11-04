package main

import (
	"log"
	"net"
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

	
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}