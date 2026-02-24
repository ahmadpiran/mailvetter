package main

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
)

// requireAPIKey is middleware that validates the Bearer token in the
// Authorization header before allowing a request through to the handler.
func requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedKey := os.Getenv("API_SECRET_KEY")

		// Failsafe: lock down the server if the operator forgot to set the key.
		// Returning 500 rather than 401 makes it immediately obvious during
		// deployment that this is a server misconfiguration, not a bad token.
		if expectedKey == "" {
			http.Error(w, "Server configuration error: API_SECRET_KEY not set", http.StatusInternalServerError)
			return
		}

		// Extract the token from the "Authorization: Bearer <token>" header.
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		token = strings.TrimSpace(token)

		// ConstantTimeCompare always examines every byte of both inputs before
		// returning, so response latency carries no information about how many
		// leading characters of the guess were correct.
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedKey)) != 1 {
			http.Error(w, `{"error": "Unauthorized: Invalid or missing API Key"}`, http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}
