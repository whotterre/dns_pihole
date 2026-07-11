package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// What do we want to do?
// We want this ....
// Load the blocklist file...global hagezi by default for everyone
// We load them into a temp map, called blocklist
// If they upload their own blocklist, we add that to the blocklist map
// Nowww, we have to check if there exists a file for the user with that IP first,
// then we assign time to the user
// We need a way to check the blocklist exists or not,
// If so, we load it....and add it's entries to our map
// To not let the folder grow too much, we introduce a bg goroutine that cleans up stale entries
var (
	blocklist map[string]bool
	mu        sync.RWMutex
)

const (
	leaseDuration   = 3 * time.Hour
	cleanupInterval = 30 * time.Minute
)

type TimeLease struct {
	UserID    string
	ExpiresAt time.Time
}

var leaseMap = make(map[string]TimeLease)

func LoadBlocklist(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read from file with bufio
	scanner := bufio.NewScanner(file)
	tempMap := make(map[string]bool)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			tempMap[line] = true
		}
	}

	if scanner.Err() != nil {
		return scanner.Err()
	}

	mu.Lock()
	blocklist = tempMap
	mu.Unlock()
	return nil
}

func IsBlocked(domain string) bool {
	mu.RLock()
	defer mu.RUnlock()
	return blocklist[domain]
}


func CreateBlacklist(ipAddr string, items []string) error {
	// Creates a blacklist or appends to an existing one for user
	blacklistFileName := fmt.Sprintf("./lists/%s", ipAddr)
	file, err := os.OpenFile(blacklistFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open/create file: %w", err)
	}
	defer file.Close()

	for _, item := range items {
		line := []byte(item + "\n")
		n, err := file.Write(line)
		if err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		if n != len(line) {
			return fmt.Errorf("wrote less than line length to file")
		}
	}

	return nil
}

func cleanupStaleEntries() {
	go func() {
		// How do we know that if something is stale..
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			// cleanup time!
			mu.Lock()
			now := time.Now()
			for id, lease := range leaseMap {
				if now.Sub(lease.ExpiresAt) > 0 {
					// deleeteeee!!!!!
					log.Printf("[Janitor] Evicting expired lease for IP/Session: %s", id)
					delete(leaseMap, id)
				} 
			}
			mu.Unlock()
		}
	}()
}
