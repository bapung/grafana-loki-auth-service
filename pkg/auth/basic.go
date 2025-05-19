package auth

import (
	"encoding/base64"
	"strings"
)

// ParseBasicAuth extracts username and password from Authorization header
func ParseBasicAuth(authHeader string) (username, password string, ok bool) {
	// Check if the header starts with "Basic "
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}

	// Get the base64-encoded credentials
	encoded := authHeader[len(prefix):]

	// Decode the base64 string
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	// Split the credentials into username and password
	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	username = parts[0]
	password = parts[1]
	return username, password, true
}
