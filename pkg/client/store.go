package client

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/lib/pq"
)

// DBProvider provides database operations for the client store
type DBProvider interface {
	Connect() error
	Close() error
	InitializeSchema() error
	GetAllClients() ([]Client, error)
	InsertOrUpdateClient(client Client) error
	DeleteClientActions(clientID string) error
	InsertClientAction(clientID, action string) error
	DeleteClient(clientID string) error
	BeginTx() (*sql.Tx, error)
}

// ClientStore holds all registered clients with database connectivity
type ClientStore struct {
	clientsByID    map[string]Client
	clientsByOrgID map[string][]Client
	db             DBProvider
	mu             sync.RWMutex
}

// NewClientStore creates a new client store with database connection
func NewClientStore(provider DBProvider) (*ClientStore, error) {
	if err := provider.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Ensure tables exist
	if err := provider.InitializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	cs := &ClientStore{
		clientsByID:    make(map[string]Client),
		clientsByOrgID: make(map[string][]Client),
		db:             provider,
	}

	// Load clients from database into memory cache
	if err := cs.refreshCache(); err != nil {
		return nil, fmt.Errorf("failed to load clients from database: %v", err)
	}

	return cs, nil
}

// refreshCache loads all clients from the database into memory
func (cs *ClientStore) refreshCache() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Clear existing cache
	cs.clientsByID = make(map[string]Client)
	cs.clientsByOrgID = make(map[string][]Client)

	clients, err := cs.db.GetAllClients()
	if err != nil {
		return err
	}

	// Add to cache
	for _, client := range clients {
		cs.clientsByID[client.ID] = client
		cs.clientsByOrgID[client.OrgID] = append(cs.clientsByOrgID[client.OrgID], client)
	}

	return nil
}

// RegisterClient adds a client to the store (both DB and cache)
func (cs *ClientStore) RegisterClient(client Client) error {
	// Process any plaintext credentials before storing
	ProcessCredentials(&client)

	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Begin transaction
	tx, err := cs.db.BeginTx()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Insert client
	if err := cs.db.InsertOrUpdateClient(client); err != nil {
		return err
	}

	// Delete existing actions
	if err := cs.db.DeleteClientActions(client.ID); err != nil {
		return err
	}

	// Insert actions
	for _, action := range client.AllowedActions {
		if err := cs.db.InsertClientAction(client.ID, action); err != nil {
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

// GetClientByID retrieves a client by ID from cache
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

func (cs *ClientStore) GetClientLength() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.clientsByID)
}

func (cs *ClientStore) GetClientByOrgIDLength(orgID string) int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.clientsByOrgID[orgID])
}

// GetAllClients returns all clients in the store
func (cs *ClientStore) GetAllClients() []Client {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	clients := make([]Client, 0, len(cs.clientsByID))
	for _, client := range cs.clientsByID {
		clients = append(clients, client)
	}
	return clients
}

// DeleteClient removes a client from the store and database
func (cs *ClientStore) DeleteClient(clientID string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Get the client to find its OrgID
	client, exists := cs.clientsByID[clientID]
	if !exists {
		return fmt.Errorf("client not found: %s", clientID)
	}

	// Delete from database
	if err := cs.db.DeleteClient(clientID); err != nil {
		return err
	}

	// Delete from clientsByID
	delete(cs.clientsByID, clientID)

	// Delete from clientsByOrgID
	orgClients := cs.clientsByOrgID[client.OrgID]
	for i, c := range orgClients {
		if c.ID == clientID {
			// Remove the client at index i
			cs.clientsByOrgID[client.OrgID] = append(orgClients[:i], orgClients[i+1:]...)
			break
		}
	}

	return nil
}
