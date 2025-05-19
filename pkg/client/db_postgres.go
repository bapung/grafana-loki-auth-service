package client

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/lib/pq"
)

// PostgresProvider is a DBProvider implementation for PostgreSQL
type PostgresProvider struct {
	connStr string
	db      *sql.DB
	mu      sync.Mutex
}

// NewPostgresProvider creates a new PostgreSQL database provider
func NewPostgresProvider(connStr string) *PostgresProvider {
	return &PostgresProvider{
		connStr: connStr,
	}
}

// Connect establishes a connection to the PostgreSQL database
func (p *PostgresProvider) Connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	db, err := sql.Open("postgres", p.connStr)
	if err != nil {
		return fmt.Errorf("failed to open PostgreSQL database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL database: %v", err)
	}

	p.db = db
	return nil
}

// InitializeSchema initializes the database schema for PostgreSQL
func (p *PostgresProvider) InitializeSchema() error {
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
			action_id SERIAL PRIMARY KEY,
			client_id TEXT NOT NULL,
			action_name TEXT NOT NULL,
			FOREIGN KEY (client_id) REFERENCES clients(id),
			UNIQUE(client_id, action_name)
		);
	`)
	return err
}

// Close closes the database connection
func (p *PostgresProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

// GetAllClients retrieves all clients from the database
func (p *PostgresProvider) GetAllClients() ([]Client, error) {
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
		actionRows, err := p.db.Query("SELECT action_name FROM client_actions WHERE client_id = $1", client.ID)
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
func (p *PostgresProvider) InsertOrUpdateClient(client Client) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec(`
		INSERT INTO clients 
		(id, org_id, basic_auth_user_hash, basic_auth_user_salt,
		basic_auth_pass_hash, basic_auth_pass_salt) 
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET 
			org_id = $2,
			basic_auth_user_hash = $3,
			basic_auth_user_salt = $4,
			basic_auth_pass_hash = $5,
			basic_auth_pass_salt = $6
	`,
		client.ID, client.OrgID,
		client.BasicAuthUserHash, client.BasicAuthUserSalt,
		client.BasicAuthPassHash, client.BasicAuthPassSalt)
	return err
}

// DeleteClientActions deletes all actions for a client
func (p *PostgresProvider) DeleteClientActions(clientID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec("DELETE FROM client_actions WHERE client_id = $1", clientID)
	return err
}

// InsertClientAction inserts an action for a client
func (p *PostgresProvider) InsertClientAction(clientID, action string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.db.Exec("INSERT INTO client_actions (client_id, action_name) VALUES ($1, $2)", clientID, action)
	return err
}

// BeginTx starts a new transaction
func (p *PostgresProvider) BeginTx() (*sql.Tx, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.db.Begin()
}
