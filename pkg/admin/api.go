package admin

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/bapung/grafana-loki-auth-service/pkg/client"
	"github.com/bapung/grafana-loki-auth-service/pkg/util"
)

// API holds dependencies for the admin API
type API struct {
	ClientStore *client.ClientStore
	AdminAPIKey string
}

// NewAPI creates a new admin API instance
func NewAPI(cs *client.ClientStore, apiKey string) *API {
	return &API{
		ClientStore: cs,
		AdminAPIKey: apiKey,
	}
}

// ClientResponse is a sanitized version of Client for API responses
type ClientResponse struct {
	ID             string   `json:"id"`
	OrgID          string   `json:"org_id"`
	AllowedActions []string `json:"allowed_actions"`
}

// CreateClientRequest represents the request body for creating a client
type CreateClientRequest struct {
	ID             string   `json:"id"`
	OrgID          string   `json:"org_id" binding:"required"`
	Username       string   `json:"username" binding:"required"`
	Password       string   `json:"password" binding:"required"`
	AllowedActions []string `json:"allowed_actions" binding:"required"`
}

// sanitizeClient removes sensitive data from a client
func sanitizeClient(c client.Client) ClientResponse {
	return ClientResponse{
		ID:             c.ID,
		OrgID:          c.OrgID,
		AllowedActions: c.AllowedActions,
	}
}

// APIKeyAuthMiddleware verifies the admin API key
func (a *API) APIKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := util.GenerateRequestID()

		// Get API key from header
		apiKey := r.Header.Get("X-Admin-API-Key")

		// Check if key is valid
		if apiKey == "" || apiKey != a.AdminAPIKey {
			log.Printf("[%s] Admin API authentication failed: Invalid or missing API key", requestID)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Authentication successful, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

// GetClientsHandler returns all clients
func (a *API) GetClientsHandler(w http.ResponseWriter, r *http.Request) {
	requestID := util.GenerateRequestID()
	log.Printf("[%s] Admin API: Get all clients request", requestID)

	// Get all clients
	clients := a.ClientStore.GetAllClients()

	// Sanitize client data
	var response []ClientResponse
	for _, c := range clients {
		response = append(response, sanitizeClient(c))
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[%s] Error encoding JSON response: %v", requestID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("[%s] Admin API: Returned %d clients", requestID, len(response))
}

// CreateClientHandler creates a new client
func (a *API) CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	requestID := util.GenerateRequestID()
	log.Printf("[%s] Admin API: Create client request", requestID)

	// Parse request body
	var req CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[%s] Error parsing request body: %v", requestID, err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.OrgID == "" || req.Username == "" || req.Password == "" || len(req.AllowedActions) == 0 {
		log.Printf("[%s] Missing required fields", requestID)
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Create client object
	newClient := client.Client{
		ID:             req.ID, // If empty, will be generated
		OrgID:          req.OrgID,
		BasicAuthUser:  req.Username,
		BasicAuthPass:  req.Password,
		AllowedActions: req.AllowedActions,
	}

	// Ensure ID is set
	if newClient.ID == "" {
		newClient.ID = util.GenerateUUID()
	}

	// Register the client
	if err := a.ClientStore.RegisterClient(newClient); err != nil {
		log.Printf("[%s] Error registering client: %v", requestID, err)
		http.Error(w, "Failed to register client", http.StatusInternalServerError)
		return
	}

	// Return created client
	response := sanitizeClient(newClient)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[%s] Error encoding JSON response: %v", requestID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("[%s] Admin API: Client created successfully with ID: %s", requestID, newClient.ID)
}

// DeleteClientHandler deletes a client by ID
func (a *API) DeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	requestID := util.GenerateRequestID()

	// Extract client ID from URL path
	path := r.URL.Path
	segments := strings.Split(path, "/")
	if len(segments) < 4 {
		log.Printf("[%s] Invalid URL path: %s", requestID, path)
		http.Error(w, "Invalid URL path", http.StatusBadRequest)
		return
	}

	clientID := segments[len(segments)-1]
	log.Printf("[%s] Admin API: Delete client request for ID: %s", requestID, clientID)

	// Check if client exists
	_, exists := a.ClientStore.GetClientByID(clientID)
	if !exists {
		log.Printf("[%s] Client not found with ID: %s", requestID, clientID)
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	// Delete the client
	if err := a.ClientStore.DeleteClient(clientID); err != nil {
		log.Printf("[%s] Error deleting client: %v", requestID, err)
		http.Error(w, "Failed to delete client", http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusNoContent)
	log.Printf("[%s] Admin API: Client deleted successfully with ID: %s", requestID, clientID)
}

// RegisterRoutes registers all admin API routes with the given router
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	// Create a subrouter with API key authentication
	adminHandler := a.APIKeyAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		method := r.Method

		switch {
		case path == "/admin/clients" && method == "GET":
			a.GetClientsHandler(w, r)
		case path == "/admin/clients" && method == "POST":
			a.CreateClientHandler(w, r)
		case strings.HasPrefix(path, "/admin/clients/") && method == "DELETE":
			a.DeleteClientHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	}))

	mux.Handle("/admin/", adminHandler)
}
