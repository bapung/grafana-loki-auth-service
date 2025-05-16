package action

import (
	"log"
	"net/http"
	"strings"

	"github.com/bapung/grafana-loki-auth-service/pkg/client"
)

var (
	LokiPathPrefix = "" // Path prefix for Loki endpoints, can be set via environment variable
)

// SetLokiPathPrefix sets the global prefix for Loki paths
func SetLokiPathPrefix(prefix string) {
	LokiPathPrefix = prefix
}

// DetermineRequestedAction analyzes the request to determine which action type it matches
// It uses path and method from query parameters if available, otherwise uses the request's actual values
func DetermineRequestedAction(r *http.Request) string {
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
		return client.ActionIngest
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
		return client.ActionQuery
	}

	// Check Status paths
	if method == "GET" && path == "/api/v1/status/buildinfo" {
		return client.ActionGetStatus
	}

	// Check Delete paths
	if (method == "POST" || method == "GET" || method == "DELETE") && path == "/api/v1/delete" {
		return client.ActionDelete
	}

	return ""
}

// IsActionAllowed checks if the requested action is in the list of allowed actions
func IsActionAllowed(requestedAction string, allowedActions []string) bool {
	for _, action := range allowedActions {
		if action == requestedAction {
			return true
		}
	}
	return false
}

// ValidateAction checks if the request path and method are allowed by the client's permissions
func ValidateAction(r *http.Request, allowedActions []string) bool {
	// Determine the action requested by this request
	action := DetermineRequestedAction(r)
	if action == "" {
		return false
	}

	// Check if the action is allowed
	return IsActionAllowed(action, allowedActions)
}
