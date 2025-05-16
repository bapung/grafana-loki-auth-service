-- Create clients table
CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    basic_auth_user_hash TEXT NOT NULL,
    basic_auth_user_salt TEXT NOT NULL,
    basic_auth_pass_hash TEXT NOT NULL,
    basic_auth_pass_salt TEXT NOT NULL
);

-- Create table for client parameters
CREATE TABLE IF NOT EXISTS client_actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    action_name TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    UNIQUE(client_id, action_name)
);
