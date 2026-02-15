package main

import (
	"net/http"
	"os"
	"strings"
)

// requireAPIKey acts as a shield around your endpoints.
// It intercepts the request, checks the Authorization header, and either
// allows it through to the handler, or rejects it with a 401 Unauthorized.
func requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedKey := os.Getenv("API_SECRET_KEY")

		// Failsafe: If you forget to set the key in production, lock down the server
		if expectedKey == "" {
			http.Error(w, "Server configuration error: API_SECRET_KEY not set", http.StatusInternalServerError)
			return
		}

		// Extract the token from the "Authorization: Bearer <token>" header
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		token = strings.TrimSpace(token)

		// Validate
		if token != expectedKey {
			http.Error(w, `{"error": "Unauthorized: Invalid or missing API Key"}`, http.StatusUnauthorized)
			return
		}

		// Key is valid, proceed to the actual endpoint
		next(w, r)
	}
}
