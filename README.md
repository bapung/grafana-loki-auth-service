# Grafana Loki Auth Service

An auth service for Grafana Loki that validates client credentials and permissions. My goal is to create a simple auth service (especially for NGINX) to enable multi-tenancy authentication and authorization in Grafana Loki.

## Features

- Basic authentication verification
- API key (TODO: Bearer)
- Client permission check: Query, Ingest, GetStatus, Delete
- Multiple database support: SQLite (default) or PostgreSQL
- Admin API for client management
- API to manage users

## Credential Storage

This service uses PBKDF2 with SHA-256 for secure credential storage. Instead of storing plaintext API keys and passwords, the system stores a hash of the credentials along with a salt.

### Generating Secure Credentials

You can use the included hash generator tool to create secure credential hashes:

```bash
go run cmd/hash-generator/main.go -plaintext="your-secret-password"
```

This will output a hash and salt that you can use in the YAML configuration file.

### Example YAML with Secure Credentials

```yaml
clients:
  - id: "client1-uuid"
    org_id: client1
    basic_auth_user_hash: "6e5d4c3b2a1..."
    basic_auth_user_salt: "f6e5d4c3b2a1..."
    basic_auth_pass_hash: "1a2b3c4d5e6f..."
    basic_auth_pass_salt: "6f5e4d3c2b1a..."
    allowed_actions:
      - Query
      - GetStatus
```

### Alternative: Using Plaintext in YAML (will be automatically hashed)

You can also provide plaintext credentials in the YAML file. The service will automatically hash them when loading:

```yaml
clients:
  - id: "client1-uuid"
    org_id: client1
    basic_auth_user: "username"  # Will be hashed on load
    basic_auth_pass: "password"  # Will be hashed on load
    allowed_actions:
      - Query
      - GetStatus
```

Note: When using plaintext credentials in YAML, they will be hashed upon first load and stored securely in the database.

## Database Configuration

This service supports two types of databases:

### SQLite (Default)

SQLite is used by default and requires minimal configuration:

```bash
# Default SQLite configuration
./auth-service

# Specify custom database path
DB_PATH=/path/to/clients.db ./auth-service
```

### PostgreSQL

To use PostgreSQL instead of SQLite:

```bash
# Required environment variables for PostgreSQL
DB_TYPE=postgres DB_CONNECTION_STRING="host=localhost port=5432 user=postgres password=secret dbname=authservice sslmode=disable" ./auth-service
```

The connection string format follows the standard PostgreSQL format.

## Database Setup

For SQLite, initialize the database schema:

```bash
go run migrations/db_migrate.go --db=./clients.db
```

For PostgreSQL, the schema will be automatically created on first run if it doesn't exist.

## Usage

### Building the Service

```bash
go build -o auth-service .
```

### Running the Service

```bash
./auth-service
```

By default, the service runs on port 8000 and uses a SQLite database at `./clients.db`.
You can change these defaults with environment variables:

```bash
PORT=9000 DB_PATH=/path/to/clients.db ./auth-service
```

### Docker Build

```bash
docker build -t auth-service:latest .
```

### Making Requests

Example valid request:

```bash
export LOKI_ADDR=https://my-loki-addr.tld
export LOKI_USERNAME=client1
export LOKI_PASSWORD=password1
logcli query --since=5m --org-id=tenant1 '{namespace="somens"} |= ""' 

```

## Kubernetes Deployment

Deploy the service and NGINX ingress using:

```bash
kubectl apply -f k8s/nginx-ingress.yaml
```

## Client Management

Clients are stored in the configured database and cached in memory for performance.

## Admin API

The service provides an admin API for managing clients, protected by an API key that you specify.

### Authentication

All admin endpoints require the `X-Admin-API-Key` header to be set with the admin API key.

```
X-Admin-API-Key: your-admin-api-key
```

### Available Endpoints

#### List All Clients

```
GET /admin/clients
```

Response:
```json
[
  {
    "id": "client1-uuid",
    "org_id": "tenant1",
    "allowed_actions": ["Query", "GetStatus"]
  },
  {
    "id": "client2-uuid",
    "org_id": "tenant2",
    "allowed_actions": ["Ingest", "Query"]
  }
]
```

#### Create Client

```
POST /admin/clients
Content-Type: application/json

{
  "id": "new-client-uuid",  // Optional, if not provided, one will be generated
  "org_id": "tenant3",
  "username": "client3",
  "password": "secure-password",
  "allowed_actions": ["Query", "GetStatus", "Ingest"]
}
```

Response:
```json
{
  "id": "new-client-uuid",
  "org_id": "tenant3",
  "allowed_actions": ["Query", "GetStatus", "Ingest"]
}
```

#### Delete Client

```
DELETE /admin/clients/{client-id}
```

Response: 204 No Content

### Configuration

To enable the admin API, set the `ADMIN_API_KEY` environment variable:

```bash
ADMIN_API_KEY="your-secure-api-key" ./auth-service
```

In Kubernetes, use a secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-service-admin-key
type: Opaque
stringData:
  admin_api_key: "your-secure-admin-api-key"
```