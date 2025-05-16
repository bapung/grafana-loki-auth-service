package client

import (
	"github.com/bapung/grafana-loki-auth-service/pkg/auth"
)

// Action types
const (
	ActionIngest    = "Ingest"
	ActionQuery     = "Query"
	ActionGetStatus = "GetStatus"
	ActionDelete    = "Delete"
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

// ProcessCredentials ensures all credentials are hashed
func ProcessCredentials(client *Client) {
	// Process basic auth username if plaintext is provided
	if client.BasicAuthUser != "" {
		if client.BasicAuthUserSalt == "" {
			client.BasicAuthUserSalt = auth.GenerateSalt()
		}
		client.BasicAuthUserHash = auth.HashCredential(client.BasicAuthUser, client.BasicAuthUserSalt)
		// Clear plaintext after hashing
		client.BasicAuthUser = ""
	}

	// Process basic auth password if plaintext is provided
	if client.BasicAuthPass != "" {
		if client.BasicAuthPassSalt == "" {
			client.BasicAuthPassSalt = auth.GenerateSalt()
		}
		client.BasicAuthPassHash = auth.HashCredential(client.BasicAuthPass, client.BasicAuthPassSalt)
		// Clear plaintext after hashing
		client.BasicAuthPass = ""
	}
}

// ClientsYAML represents the structure of the YAML file containing client configurations
type ClientsYAML struct {
	Clients []Client `yaml:"clients"`
}
