package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltSize       = 16
	HashIterations = 10000
	HashKeyLength  = 32
)

func generateSalt() string {
	saltBytes := make([]byte, SaltSize)
	_, err := rand.Read(saltBytes)
	if err != nil {
		fmt.Printf("Failed to generate salt: %v\n", err)
		os.Exit(1)
	}
	return hex.EncodeToString(saltBytes)
}

func hashCredential(credential, salt string) string {
	hash := pbkdf2.Key([]byte(credential), []byte(salt), HashIterations, HashKeyLength, sha256.New)
	return hex.EncodeToString(hash)
}

func main() {
	var (
		plaintext = flag.String("plaintext", "", "The plaintext credential to hash")
		salt      = flag.String("salt", "", "Salt to use (optional, will generate if not provided)")
	)

	flag.Parse()

	if *plaintext == "" {
		fmt.Println("Error: Plaintext credential is required")
		fmt.Println("Usage: hash-generator -plaintext=YOUR_CREDENTIAL [-salt=OPTIONAL_SALT]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	saltValue := *salt
	if saltValue == "" {
		saltValue = generateSalt()
		fmt.Printf("Generated salt: %s\n", saltValue)
	}

	hashValue := hashCredential(*plaintext, saltValue)

	fmt.Println("\nYAML Configuration:")
	fmt.Printf("credential_hash: \"%s\"\n", hashValue)
	fmt.Printf("credential_salt: \"%s\"\n", saltValue)
}
