package client

import (
	"database/sql"
	"fmt"
	"sync"
)

// ClientStore holds all registered clients with database connectivity
type ClientStore struct {
	clientsByID    map[string]Client
	clientsByOrgID map[string][]Client
	db             *sql.DB
	mu             sync.RWMutex
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
	ProcessCredentials(&client)

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
