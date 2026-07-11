package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

func SetupRoutes(app *http.ServeMux) {
	app.HandleFunc("/blocklist/add", AddToBlocklist)
}

func AddToBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	// Extract Client IP
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	// Read the cookie
	var userID string
	cookie, err := r.Cookie("user_id")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			userID = fmt.Sprintf("%d", time.Now().Unix())

			cookie := &http.Cookie{
				Name:     "user_id",
				Value:    userID,
				Path:     "/",
				MaxAge:   86400 * 365 * 5,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}

			http.SetCookie(w, cookie)

			log.Println("No cookie found. Generating a new ID...")

			log.Printf("Successfully set new long-lived cookie ID: %s", userID)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		existingID := cookie.Value
		log.Printf("Found existing user ID from cookie: %s", existingID)

		// Read the request body
		type ListRequest struct {
			Entries []string `json:"entries"`
		}

		var req ListRequest

		err = json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		err = CreateBlacklist(existingID, req.Entries)
		if err != nil {
			http.Error(w, "Failed to save blocklist", http.StatusInternalServerError)
			return
		}

		mu.Lock()
		if leaseMap == nil {
			leaseMap = make(map[string]TimeLease)
		}
		leaseMap[clientIP] = TimeLease{
			UserID:    userID,
			ExpiresAt: time.Now().Add(leaseDuration),
		}

		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","message":"Blocklist synced and lease activated"}`))
	}
}
