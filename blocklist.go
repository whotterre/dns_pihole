package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	blocklist map[string]bool
	mu sync.RWMutex
)

func LoadBlocklist(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open blocklist: %w", err)
	}
	defer file.Close()

	tempMap := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tempMap[line] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocklist: %w", err)
	}

	mu.Lock()
	blocklist = tempMap
	mu.Unlock()

	log.Printf("Loaded %d blocked domains", len(blocklist))
	return nil
}

func IsBlocked(domain string) bool {
	// We usually get responses in the form of "google.com.
	// With a trailing ., this removes that"
	domain = strings.TrimSuffix(domain, ".")
	
	mu.RLock()
	defer mu.RUnlock()

	return blocklist[domain]
}
