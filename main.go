package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"
)

// Action types
const (
	ActionIngest    = "Ingest"
	ActionQuery     = "Query"
	ActionGetStatus = "GetStatus"
	ActionDelete    = "Delete"
)

// Global configuration
var (
	LokiPathPrefix = "" // Path prefix for Loki endpoints, can be set via environment variable
)

// Client represents an authenticated client with permissions
type Client struct {
	ID                string   `yaml:"id"`
	OrgID             string   `yaml:"org_id"`
	BasicAuthUserHash string   `yaml:"basic_auth_user_hash"`
	BasicAuthUserSalt string   `yaml:"basic_auth_user_salt"`
	BasicAuthPassHash string   `yaml:"basic_auth_pass_hash"`
	BasicAuthPassSalt string   `yaml:"basic_auth_pass_salt"`
	AllowedActions    []string `yaml:"allowed_actions"`

	// Not stored in DB, only used when loading from YAML
	BasicAuthUser string `yaml:"basic_auth_user,omitempty"`
	BasicAuthPass string `yaml:"basic_auth_pass,omitempty"`
}

// ClientStore holds all registered clients with database connectivity
type ClientStore struct {
	clientsByID    map[string]Client
	clientsByOrgID map[string][]Client
	db             *sql.DB
	mu             sync.RWMutex
}

// ClientsYAML represents the structure of the YAML file containing client configurations
type ClientsYAML struct {
	Clients []Client `yaml:"clients"`
}

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

// ProcessClientCredentials ensures all credentials are hashed
func ProcessClientCredentials(client *Client) {
	// Process basic auth username if plaintext is provided
	if client.BasicAuthUser != "" {
		if client.BasicAuthUserSalt == "" {
			client.BasicAuthUserSalt = GenerateSalt()
		}
		client.BasicAuthUserHash = HashCredential(client.BasicAuthUser, client.BasicAuthUserSalt)
		// Clear plaintext after hashing
		client.BasicAuthUser = ""
	}

	// Process basic auth password if plaintext is provided
	if client.BasicAuthPass != "" {
		if client.BasicAuthPassSalt == "" {
			client.BasicAuthPassSalt = GenerateSalt()
		}
		client.BasicAuthPassHash = HashCredential(client.BasicAuthPass, client.BasicAuthPassSalt)
		// Clear plaintext after hashing
		client.BasicAuthPass = ""
	}
}

// CompareCredentials compares a plaintext credential against stored hash and salt
func CompareCredentials(plaintext, hash, salt string) bool {
	computedHash := HashCredential(plaintext, salt)
	return computedHash == hash
}

// NewClientStore creates a new client store with database connection
func NewClientStore(dbPath string) (*ClientStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Ensure tables exist
	if err := initializeDatabase(db); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	cs := &ClientStore{
		clientsByID:    make(map[string]Client),
		clientsByOrgID: make(map[string][]Client),
		db:             db,
	}

	// Load clients from database into memory cache
	if err := cs.refreshCache(); err != nil {
		return nil, fmt.Errorf("failed to load clients from database: %v", err)
	}

	// If no clients found in the database, try loading from YAML file
	if len(cs.clientsByID) == 0 {
		yamlPath := os.Getenv("CLIENTS_YAML_PATH")
		if yamlPath == "" {
			yamlPath = "./authorized_clients.yaml"
		}

		clients, err := loadClientsFromYAML(yamlPath)
		if err != nil {
			log.Printf("No clients in database and failed to load from YAML: %v", err)
		} else {
			log.Printf("Loaded %d clients from YAML file", len(clients))
			for _, client := range clients {
				if err := cs.RegisterClient(client); err != nil {
					return nil, fmt.Errorf("failed to register client from YAML: %v", err)
				}
			}
		}
	}

	return cs, nil
}

// initializeDatabase creates necessary tables if they don't exist
func initializeDatabase(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			basic_auth_user_hash TEXT NOT NULL,
			basic_auth_user_salt TEXT NOT NULL,
			basic_auth_pass_hash TEXT NOT NULL,
			basic_auth_pass_salt TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS client_actions (
			action_id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_id TEXT NOT NULL,
			action_name TEXT NOT NULL,
			FOREIGN KEY (client_id) REFERENCES clients(id),
			UNIQUE(client_id, action_name)
		);
	`)
	return err
}

// loadClientsFromYAML loads client configurations from a YAML file
func loadClientsFromYAML(filePath string) ([]Client, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read YAML file: %v", err)
	}

	var clientsYAML ClientsYAML
	if err := yaml.Unmarshal(data, &clientsYAML); err != nil {
		return nil, fmt.Errorf("could not parse YAML: %v", err)
	}

	// Process any plaintext credentials in YAML
	for i := range clientsYAML.Clients {
		ProcessClientCredentials(&clientsYAML.Clients[i])
	}

	return clientsYAML.Clients, nil
}

// refreshCache loads all clients from the database into memory
func (cs *ClientStore) refreshCache() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Clear existing cache
	cs.clientsByID = make(map[string]Client)
	cs.clientsByOrgID = make(map[string][]Client)

	// Query all clients
	rows, err := cs.db.Query(`SELECT id, org_id, 
							 basic_auth_user_hash, basic_auth_user_salt,
							 basic_auth_pass_hash, basic_auth_pass_salt
							 FROM clients`)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Process each client
	for rows.Next() {
		var client Client
		if err := rows.Scan(
			&client.ID,
			&client.OrgID,
			&client.BasicAuthUserHash,
			&client.BasicAuthUserSalt,
			&client.BasicAuthPassHash,
			&client.BasicAuthPassSalt); err != nil {
			return err
		}

		// Query allowed actions for this client
		actionRows, err := cs.db.Query("SELECT action_name FROM client_actions WHERE client_id = ?", client.ID)
		if err != nil {
			return err
		}
		defer actionRows.Close()

		// Load actions
		var actions []string
		for actionRows.Next() {
			var action string
			if err := actionRows.Scan(&action); err != nil {
				return err
			}
			actions = append(actions, action)
		}
		client.AllowedActions = actions

		// Add to cache
		cs.clientsByID[client.ID] = client
		cs.clientsByOrgID[client.OrgID] = append(cs.clientsByOrgID[client.OrgID], client)
	}

	return rows.Err()
}

// RegisterClient adds a client to the store (both DB and cache)
func (cs *ClientStore) RegisterClient(client Client) error {
	// Process any plaintext credentials before storing
	ProcessClientCredentials(&client)

	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Begin transaction
	tx, err := cs.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Insert client
	_, err = tx.Exec(`INSERT OR REPLACE INTO clients 
					 (id, org_id, basic_auth_user_hash, basic_auth_user_salt,
					 basic_auth_pass_hash, basic_auth_pass_salt) 
					 VALUES (?, ?, ?, ?, ?, ?)`,
		client.ID, client.OrgID,
		client.BasicAuthUserHash, client.BasicAuthUserSalt,
		client.BasicAuthPassHash, client.BasicAuthPassSalt)
	if err != nil {
		return err
	}

	// Delete existing actions
	_, err = tx.Exec("DELETE FROM client_actions WHERE client_id = ?", client.ID)
	if err != nil {
		return err
	}

	// Insert actions
	for _, action := range client.AllowedActions {
		_, err = tx.Exec("INSERT INTO client_actions (client_id, action_name) VALUES (?, ?)", client.ID, action)
		if err != nil {
			return err
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return err
	}

	// Update cache
	cs.clientsByID[client.ID] = client

	// Update the clientsByOrgID map
	found := false
	for i, existingClient := range cs.clientsByOrgID[client.OrgID] {
		if existingClient.ID == client.ID {
			// Replace existing client
			cs.clientsByOrgID[client.OrgID][i] = client
			found = true
			break
		}
	}

	if !found {
		// Add new client
		cs.clientsByOrgID[client.OrgID] = append(cs.clientsByOrgID[client.OrgID], client)
	}

	return nil
}

// GetClientsByOrgID retrieves all clients for a specific OrgID from cache
func (cs *ClientStore) GetClientsByOrgID(orgID string) []Client {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.clientsByOrgID[orgID]
}

// GetClient retrieves a client by ID from cache
func (cs *ClientStore) GetClientByID(id string) (Client, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	client, exists := cs.clientsByID[id]
	return client, exists
}

// Close closes the database connection
func (cs *ClientStore) Close() error {
	return cs.db.Close()
}

func main() {
	// Get database path from environment or use default
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./clients.db"
	}

	// Get Loki path prefix from environment variable
	LokiPathPrefix = os.Getenv("LOKI_PATH_PREFIX")
	if LokiPathPrefix != "" && !strings.HasSuffix(LokiPathPrefix, "/") {
		// Ensure the prefix doesn't end with a slash to correctly join with paths
		LokiPathPrefix = LokiPathPrefix + "/"
	}

	// Log the Loki path prefix if set
	if LokiPathPrefix != "" {
		log.Printf("Using Loki path prefix: %s", LokiPathPrefix)
	}

	// Initialize client store
	clientStore, err := NewClientStore(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize client store: %v", err)
	}
	defer clientStore.Close()

	// Check if there are any clients available
	if len(clientStore.clientsByID) == 0 {
		log.Fatalf("No clients found in database or YAML file. Cannot start the service without clients.")
	}

	// Setup HTTP server
	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		validateHandler(w, r, clientStore)
	})

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	log.Printf("Starting auth service on port %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func validateHandler(w http.ResponseWriter, r *http.Request, cs *ClientStore) {
	// Log the incoming request details
	requestID := generateRequestID()
	log.Printf("[%s] Validation request: Method=%s, Path=%s", requestID, r.Method, r.URL.Path)

	// Extract OrgID from header
	orgID := r.Header.Get("X-Scope-OrgId")
	if orgID == "" {
		log.Printf("[%s] Validation failed: Missing X-Scope-OrgId header", requestID)
		http.Error(w, "Missing X-Scope-OrgId header", http.StatusUnauthorized)
		return
	}
	log.Printf("[%s] OrgID found: %s", requestID, orgID)

	// Get all clients for this OrgID
	clients := cs.GetClientsByOrgID(orgID)
	if len(clients) == 0 {
		log.Printf("[%s] Validation failed: No clients found for OrgID: %s", requestID, orgID)
		http.Error(w, "Unknown client", http.StatusUnauthorized)
		return
	}
	log.Printf("[%s] Found %d client(s) for OrgID: %s", requestID, len(clients), orgID)

	// Log query parameters (excluding sensitive data)
	logQueryParams(requestID, r.URL.Query())

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Printf("[%s] Validation failed: Missing Authorization header", requestID)
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Only log auth header presence, not content
	log.Printf("[%s] Authorization header present: %t", requestID, authHeader != "")

	// Extract username and password from basic auth
	username, password, ok := parseBasicAuth(authHeader)
	if !ok {
		log.Printf("[%s] Validation failed: Invalid authorization header format", requestID)
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	// Only log username presence, not the actual username or password
	log.Printf("[%s] Basic auth credentials present: %t", requestID, username != "" && password != "")

	// Try to find a matching client based on credentials
	var validClient *Client
	for i, client := range clients {
		// Check basic auth
		basicAuthValid := CompareCredentials(username, client.BasicAuthUserHash, client.BasicAuthUserSalt) &&
			CompareCredentials(password, client.BasicAuthPassHash, client.BasicAuthPassSalt)

		if basicAuthValid {
			validClient = &clients[i]
			log.Printf("[%s] Credentials matched for client ID: %s", requestID, client.ID)
			break
		}
	}

	if validClient == nil {
		log.Printf("[%s] Validation failed: Invalid credentials for OrgID: %s", requestID, orgID)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Validate request path and method against allowed actions
	originalPath := r.URL.Query().Get("path")
	originalMethod := r.URL.Query().Get("method")
	action := determineRequestedAction(r)
	if action == "" {
		log.Printf("[%s] Validation failed: Could not determine action for path: %s method: %s",
			requestID, originalPath, originalMethod)
		http.Error(w, "Unknown action requested", http.StatusForbidden)
		return
	}

	log.Printf("[%s] Requested action: %s, path: %s, method: %s", requestID, action, originalPath, r.Method)
	log.Printf("[%s] Client allowed actions: %v", requestID, validClient.AllowedActions)

	if !isActionAllowed(action, validClient.AllowedActions) {
		log.Printf("[%s] Validation failed: Action not allowed. Requested: %s, Allowed: %v",
			requestID, action, validClient.AllowedActions)
		http.Error(w, "Action not allowed", http.StatusForbidden)
		return
	}

	// All validations passed
	log.Printf("[%s] Authorization successful for client: %s (ID: %s)", requestID, orgID, validClient.ID)
	w.WriteHeader(http.StatusOK)
}

// logQueryParams logs query parameters, hiding sensitive information
func logQueryParams(requestID string, params map[string][]string) {
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

// generateRequestID creates a unique ID for each request for tracking through logs
func generateRequestID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// determineRequestedAction analyzes the request to determine which action type it matches
// It uses path and method from query parameters if available, otherwise uses the request's actual values
func determineRequestedAction(r *http.Request) string {
	// Get path and method from query parameters if available
	queryPath := r.URL.Query().Get("path")
	queryMethod := r.URL.Query().Get("method")

	// Use query params if available, otherwise use actual request path/method
	path := r.URL.Path
	method := r.Method

	if queryPath != "" {
		path = queryPath
		log.Printf("Using path from query parameter: %s", path)
	}

	if queryMethod != "" {
		method = queryMethod
		log.Printf("Using method from query parameter: %s", method)
	}

	// Strip any query parameters from the path
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
		log.Printf("Stripped query parameters from path: %s", path)
	}

	// If path prefix is configured, strip it for validation
	if LokiPathPrefix != "" && strings.HasPrefix(path, LokiPathPrefix) {
		path = strings.TrimPrefix(path, LokiPathPrefix)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}

	log.Printf("Stripped prefix from path: %s", path)

	// Check Ingest paths
	if method == "POST" && (path == "/api/v1/push" || path == "/v1/logs") {
		return ActionIngest
	}

	// Check Query paths
	if method == "GET" && (path == "/api/v1/query" ||
		path == "/api/v1/query_range" ||
		path == "/api/v1/labels" ||
		strings.HasPrefix(path, "/api/v1/label/") && strings.HasSuffix(path, "/values") ||
		path == "/api/v1/series" ||
		path == "/api/v1/index/stats" ||
		path == "/api/v1/index/volume" ||
		path == "/api/v1/index/volume_range" ||
		path == "/api/v1/patterns" ||
		path == "/api/v1/tail") {
		return ActionQuery
	}

	// Check Status paths
	if method == "GET" && path == "/api/v1/status/buildinfo" {
		return ActionGetStatus
	}

	// Check Delete paths
	if (method == "POST" || method == "GET" || method == "DELETE") && path == "/api/v1/delete" {
		return ActionDelete
	}

	return ""
}

// isActionAllowed checks if the requested action is in the list of allowed actions
func isActionAllowed(requestedAction string, allowedActions []string) bool {
	for _, action := range allowedActions {
		if action == requestedAction {
			return true
		}
	}
	return false
}

// validateAction checks if the request path and method are allowed by the client's permissions
func validateAction(r *http.Request, allowedActions []string) bool {
	// Determine the action requested by this request
	action := determineRequestedAction(r)
	if action == "" {
		return false
	}

	// Check if the action is allowed
	return isActionAllowed(action, allowedActions)
}

// parseBasicAuth extracts username and password from Authorization header
func parseBasicAuth(authHeader string) (username, password string, ok bool) {
	// Check if the header starts with "Basic "
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}

	// Get the base64-encoded credentials
	encoded := authHeader[len(prefix):]

	// Decode the base64 string
	decoded, err := decodeBase64(encoded)
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

// decodeBase64 decodes a base64 string to bytes
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
