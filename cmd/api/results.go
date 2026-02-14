package main

import (
	"encoding/json"
	"net/http"

	"mailvetter/internal/store"
)

// ResultRow represents a single verified email from the database
type ResultRow struct {
	Email string          `json:"email"`
	Score int             `json:"score"`
	Data  json.RawMessage `json:"data"` // RawMessage prevents Go from escaping the JSONB object
}

func resultsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobID := r.URL.Query().Get("id")
	if jobID == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Query the results table, ordered by the sequence they were saved
	query := `SELECT email, score, data FROM results WHERE job_id = $1 ORDER BY id ASC`

	rows, err := store.DB.Query(ctx, query, jobID)
	if err != nil {
		http.Error(w, "Failed to fetch results", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []ResultRow

	for rows.Next() {
		var row ResultRow
		if err := rows.Scan(&row.Email, &row.Score, &row.Data); err != nil {
			continue // Skip malformed rows
		}
		results = append(results, row)
	}

	// Ensure we return an empty array `[]` instead of `null` if no results are found yet
	if results == nil {
		results = []ResultRow{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
