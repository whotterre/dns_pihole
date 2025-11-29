package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

var blocklist map[string]bool

func LoadBlocklist(filePath string) error {
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

func IsBlocked(domain string) bool {
	return blocklist[domain]
}
