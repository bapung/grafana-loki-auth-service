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
