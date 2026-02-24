package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"mailvetter/internal/store"
)

// ResultRow represents a single verified email row returned by the API.
type ResultRow struct {
	Email string          `json:"email"`
	Score int             `json:"score"`
	Data  json.RawMessage `json:"data"`
}

// ResultsPage wraps a page of results with metadata the client needs to
// paginate without making a separate count query.
type ResultsPage struct {
	JobID      string      `json:"job_id"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalCount int         `json:"total_count"`
	HasMore    bool        `json:"has_more"`
	Results    []ResultRow `json:"results"`
}

const (
	defaultPageSize = 500
	maxPageSize     = 2000
)

// resultsHandler returns a single page of verification results for a job.
//
// Query parameters:
//
//	id        — job UUID (required)
//	page      — 1-based page number (default: 1)
//	page_size — rows per page (default: 500, max: 2000)
//
// The composite index idx_results_job_id_id added in the issue #5 fix means
// the LIMIT/OFFSET query is resolved entirely via index scan — no sort step,
// no sequential scan, constant memory on the server side regardless of job size.
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

	// Parse page (1-based).
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	// Parse page_size, clamped to [1, maxPageSize].
	pageSize := defaultPageSize
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	offset := (page - 1) * pageSize
	ctx := r.Context()

	// Fetch total_count from the jobs table so we can populate has_more and
	// total_count in the response without a separate COUNT(*) on results.
	// This is a single indexed primary-key lookup — effectively free.
	var totalCount int
	err := store.DB.QueryRow(ctx,
		`SELECT total_count FROM jobs WHERE id = $1`, jobID,
	).Scan(&totalCount)
	if err != nil {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	// Fetch exactly one page of results using the composite index
	// (job_id, id) added in the issue #5 fix. The index satisfies both the
	// WHERE clause and the ORDER BY in a single scan with no sort step.
	rows, err := store.DB.Query(ctx, `
		SELECT email, score, data
		FROM   results
		WHERE  job_id = $1
		ORDER  BY id ASC
		LIMIT  $2
		OFFSET $3
	`, jobID, pageSize, offset)
	if err != nil {
		http.Error(w, "Failed to fetch results", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	results := make([]ResultRow, 0, pageSize)
	for rows.Next() {
		var row ResultRow
		if err := rows.Scan(&row.Email, &row.Score, &row.Data); err != nil {
			continue
		}
		results = append(results, row)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Error reading results", http.StatusInternalServerError)
		return
	}

	resp := ResultsPage{
		JobID:      jobID,
		Page:       page,
		PageSize:   pageSize,
		TotalCount: totalCount,
		HasMore:    offset+len(results) < totalCount,
		Results:    results,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
