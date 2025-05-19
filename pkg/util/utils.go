package util

import (
	"crypto/rand"
	"fmt"
	"log"
	"strings"
)

// GenerateRequestID creates a unique ID for each request for tracking through logs
func GenerateRequestID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// LogQueryParams logs query parameters, hiding sensitive information
func LogQueryParams(requestID string, params map[string][]string) {
	// Create a copy of params to avoid modifying the original
	sanitized := make(map[string]interface{})

	// Copy all params except sensitive ones
	for key, values := range params {
		// Skip logging sensitive parameters
		if key == "key" || strings.Contains(strings.ToLower(key), "password") ||
			strings.Contains(strings.ToLower(key), "token") || strings.Contains(strings.ToLower(key), "auth") {
			sanitized[key] = "[REDACTED]"
		} else if len(values) == 1 {
			sanitized[key] = values[0]
		} else {
			sanitized[key] = values
		}
	}

	log.Printf("[%s] Query parameters: %v", requestID, sanitized)
}

// GenerateUUID creates a UUID v4 for use as client IDs
func GenerateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Failed to generate UUID: %v", err)
	}

	// Set version (4) and variant bits
	b[6] = (b[6] & 0x0F) | 0x40
	b[8] = (b[8] & 0x3F) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
