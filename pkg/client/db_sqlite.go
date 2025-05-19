package client

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteProvider is a DBProvider implementation for SQLite
type SQLiteProvider struct {
	dbPath string
	db     *sql.DB
	mu     sync.Mutex
}

// NewSQLiteProvider creates a new SQLite database provider
func NewSQLiteProvider(dbPath string) *SQLiteProvider {
	return &SQLiteProvider{
		dbPath: dbPath,
	}
}

// Connect establishes a connection to the SQLite database
func (p *SQLiteProvider) Connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	db, err := sql.Open("sqlite3", p.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to connect to SQLite database: %v", err)
	}

	p.db = db
	return nil
}

// InitializeSchema initializes the database schema for SQLite
func (p *SQLiteProvider) InitializeSchema() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec(`
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

// Close closes the database connection
func (p *SQLiteProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

// GetAllClients retrieves all clients from the database
func (p *SQLiteProvider) GetAllClients() ([]Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	clients := []Client{}

	// Query all clients
	rows, err := p.db.Query(`SELECT id, org_id, 
							 basic_auth_user_hash, basic_auth_user_salt,
							 basic_auth_pass_hash, basic_auth_pass_salt
							 FROM clients`)
	if err != nil {
		return nil, err
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
			return nil, err
		}

		// Query allowed actions for this client
		actionRows, err := p.db.Query("SELECT action_name FROM client_actions WHERE client_id = ?", client.ID)
		if err != nil {
			return nil, err
		}

		// Load actions
		var actions []string
		for actionRows.Next() {
			var action string
			if err := actionRows.Scan(&action); err != nil {
				actionRows.Close()
				return nil, err
			}
			actions = append(actions, action)
		}
		actionRows.Close()

		client.AllowedActions = actions
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}

// InsertOrUpdateClient inserts or updates a client in the database
func (p *SQLiteProvider) InsertOrUpdateClient(client Client) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec(`INSERT OR REPLACE INTO clients 
					 (id, org_id, basic_auth_user_hash, basic_auth_user_salt,
					 basic_auth_pass_hash, basic_auth_pass_salt) 
					 VALUES (?, ?, ?, ?, ?, ?)`,
		client.ID, client.OrgID,
		client.BasicAuthUserHash, client.BasicAuthUserSalt,
		client.BasicAuthPassHash, client.BasicAuthPassSalt)
	return err
}

// DeleteClientActions deletes all actions for a client
func (p *SQLiteProvider) DeleteClientActions(clientID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec("DELETE FROM client_actions WHERE client_id = ?", clientID)
	return err
}

// InsertClientAction inserts an action for a client
func (p *SQLiteProvider) InsertClientAction(clientID, action string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec("INSERT INTO client_actions (client_id, action_name) VALUES (?, ?)", clientID, action)
	return err
}

// BeginTx starts a new transaction
func (p *SQLiteProvider) BeginTx() (*sql.Tx, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.db.Begin()
}

// DeleteClient deletes a client and its associated actions
func (p *SQLiteProvider) DeleteClient(clientID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Begin transaction
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Delete client actions first due to foreign key constraint
	_, err = tx.Exec("DELETE FROM client_actions WHERE client_id = ?", clientID)
	if err != nil {
		return err
	}

	// Delete the client
	_, err = tx.Exec("DELETE FROM clients WHERE id = ?", clientID)
	if err != nil {
		return err
	}

	// Commit transaction
	return tx.Commit()
}
