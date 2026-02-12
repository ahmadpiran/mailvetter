package main

import (
	"encoding/json"
	"net/http"
	"time"

	"mailvetter/internal/store"
)

type JobStatusResponse struct {
	ID             string     `json:"id"`
	Status         string     `json:"status"`
	TotalCount     int        `json:"total_count"`
	ProcessedCount int        `json:"processed_count"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
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
	var job JobStatusResponse

	query := `
		SELECT id, status, total_count, processed_count, created_at, completed_at 
		FROM jobs 
		WHERE id = $1
	`

	err := store.DB.QueryRow(ctx, query, jobID).Scan(
		&job.ID,
		&job.Status,
		&job.TotalCount,
		&job.ProcessedCount,
		&job.CreatedAt,
		&job.CompletedAt,
	)

	if err != nil {
		// If no rows found, it means the ID is wrong
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}
