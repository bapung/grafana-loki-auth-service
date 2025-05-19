package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

// Credential hashing constants
const (
	SaltSize       = 16
	HashIterations = 10000
	HashKeyLength  = 32
)

// HashCredential hashes a credential with a salt using PBKDF2
func HashCredential(credential, salt string) string {
	if salt == "" {
		saltBytes := make([]byte, SaltSize)
		_, err := rand.Read(saltBytes)
		if err != nil {
			log.Fatalf("Failed to generate salt: %v", err)
		}
		salt = hex.EncodeToString(saltBytes)
	}

	hash := pbkdf2.Key([]byte(credential), []byte(salt), HashIterations, HashKeyLength, sha256.New)
	return hex.EncodeToString(hash)
}

// GenerateSalt creates a new random salt
func GenerateSalt() string {
	saltBytes := make([]byte, SaltSize)
	_, err := rand.Read(saltBytes)
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}
	return hex.EncodeToString(saltBytes)
}

// CompareCredentials compares a plaintext credential against stored hash and salt
func CompareCredentials(plaintext, hash, salt string) bool {
	computedHash := HashCredential(plaintext, salt)
	return computedHash == hash
}
