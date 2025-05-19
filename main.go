package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"github.com/bapung/grafana-loki-auth-service/pkg/action"
	"github.com/bapung/grafana-loki-auth-service/pkg/admin"
	"github.com/bapung/grafana-loki-auth-service/pkg/auth"
	"github.com/bapung/grafana-loki-auth-service/pkg/client"
	"github.com/bapung/grafana-loki-auth-service/pkg/util"
)

func main() {
	// Get database type from environment or use default
	dbType := os.Getenv("DB_TYPE")
	if dbType == "" {
		dbType = "sqlite" // Default to SQLite
	}

	// Initialize database provider based on the selected type
	var dbProvider client.DBProvider

	switch strings.ToLower(dbType) {
	case "sqlite":
		// Get SQLite database path from environment or use default
		dbPath := os.Getenv("DB_PATH")
		if dbPath == "" {
			dbPath = "./clients.db"
		}
		log.Printf("Using SQLite database at: %s", dbPath)
		dbProvider = client.NewSQLiteProvider(dbPath)

	case "postgres", "postgresql":
		// Get PostgreSQL connection string from environment
		connStr := os.Getenv("DB_CONNECTION_STRING")
		if connStr == "" {
			log.Fatalf("PostgreSQL connection string not provided. Set DB_CONNECTION_STRING environment variable.")
		}
		log.Printf("Using PostgreSQL database")
		dbProvider = client.NewPostgresProvider(connStr)

	default:
		log.Fatalf("Unsupported database type: %s. Supported types: sqlite, postgres", dbType)
	}

	// Get Loki path prefix from environment variable
	lokiPathPrefix := os.Getenv("LOKI_PATH_PREFIX")
	if lokiPathPrefix != "" && !strings.HasSuffix(lokiPathPrefix, "/") {
		// Ensure the prefix doesn't end with a slash to correctly join with paths
		lokiPathPrefix = lokiPathPrefix + "/"
	}

	// Set the global Loki path prefix
	action.SetLokiPathPrefix(lokiPathPrefix)

	// Log the Loki path prefix if set
	if lokiPathPrefix != "" {
		log.Printf("Using Loki path prefix: %s", lokiPathPrefix)
	}

	// Initialize client store
	clientStore, err := client.NewClientStore(dbProvider)
	if err != nil {
		log.Fatalf("Failed to initialize client store: %v", err)
	}
	defer clientStore.Close()

	// If no clients found in the database, try loading from YAML file
	if len(clientStore.GetClientsByOrgID("")) == 0 {
		yamlPath := os.Getenv("CLIENTS_YAML_PATH")
		if yamlPath == "" {
			yamlPath = "./authorized_clients.yaml"
		}

		clients, err := client.LoadFromYAML(yamlPath)
		if err != nil {
			log.Printf("No clients in database and failed to load from YAML: %v", err)
		} else {
			log.Printf("Loaded %d clients from YAML file", len(clients))
			for _, c := range clients {
				if err := clientStore.RegisterClient(c); err != nil {
					log.Fatalf("Failed to register client from YAML: %v", err)
				}
			}
		}
	}

	// Check if there are any clients available
	if clientStore.GetClientLength() == 0 {
		log.Fatalf("No clients found in database or YAML file. Cannot start the service without clients.")
	}

	// Get admin API key from environment variable
	adminAPIKey := os.Getenv("ADMIN_API_KEY")
	if adminAPIKey == "" {
		log.Printf("WARNING: Admin API key not set! Admin endpoints will be disabled.")
	} else {
		log.Printf("Admin API is enabled and secured with API key")
	}

	// Create HTTP server mux
	mux := http.NewServeMux()

	// Register validate endpoint
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		validateHandler(w, r, clientStore)
	})

	// Register admin endpoints if API key is provided
	if adminAPIKey != "" {
		adminAPI := admin.NewAPI(clientStore, adminAPIKey)
		adminAPI.RegisterRoutes(mux)
	}

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	log.Printf("Starting auth service on port %s...", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func validateHandler(w http.ResponseWriter, r *http.Request, cs *client.ClientStore) {
	// Log the incoming request details
	requestID := util.GenerateRequestID()
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
	util.LogQueryParams(requestID, r.URL.Query())

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Printf("[%s] Validation failed: Missing Authorization header", requestID)
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Only log auth header presence, not content
	log.Printf("[%s] Authorization header present: %t", requestID, authHeader != "")

	// Extract username and password from basic auth
	username, password, ok := auth.ParseBasicAuth(authHeader)
	if !ok {
		log.Printf("[%s] Validation failed: Invalid authorization header format", requestID)
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	// Only log username presence, not the actual username or password
	log.Printf("[%s] Basic auth credentials present: %t", requestID, username != "" && password != "")

	// Try to find a matching client based on credentials
	var validClient *client.Client
	for i, c := range clients {
		// Check basic auth
		basicAuthValid := auth.CompareCredentials(username, c.BasicAuthUserHash, c.BasicAuthUserSalt) &&
			auth.CompareCredentials(password, c.BasicAuthPassHash, c.BasicAuthPassSalt)

		if basicAuthValid {
			validClient = &clients[i]
			log.Printf("[%s] Credentials matched for client ID: %s", requestID, c.ID)
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
	requestedAction := action.DetermineRequestedAction(r)
	if requestedAction == "" {
		log.Printf("[%s] Validation failed: Could not determine action for path: %s method: %s",
			requestID, originalPath, originalMethod)
		http.Error(w, "Unknown action requested", http.StatusForbidden)
		return
	}

	log.Printf("[%s] Requested action: %s, path: %s, method: %s", requestID, requestedAction, originalPath, r.Method)
	log.Printf("[%s] Client allowed actions: %v", requestID, validClient.AllowedActions)

	if !action.IsActionAllowed(requestedAction, validClient.AllowedActions) {
		log.Printf("[%s] Validation failed: Action not allowed. Requested: %s, Allowed: %v",
			requestID, requestedAction, validClient.AllowedActions)
		http.Error(w, "Action not allowed", http.StatusForbidden)
		return
	}

	// All validations passed
	log.Printf("[%s] Authorization successful for client: %s (ID: %s)", requestID, orgID, validClient.ID)
	w.WriteHeader(http.StatusOK)
}
