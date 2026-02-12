package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"mailvetter/internal/store"

	"github.com/google/uuid"
)

// UploadResponse is what we send back to the user
type UploadResponse struct {
	JobID     string `json:"job_id"`
	TotalRows int    `json:"total_rows"`
	Message   string `json:"message"`
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Only allow POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. Parse Multipart Form (Max 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "File too large or malformed", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Missing 'file' parameter in form data", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 3. Read CSV
	reader := csv.NewReader(file)
	var emails []string

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Invalid CSV format", http.StatusBadRequest)
			return
		}

		// Assume email is in the first column (simple for now)
		if len(record) > 0 && record[0] != "" {
			emails = append(emails, record[0])
		}
	}

	if len(emails) == 0 {
		http.Error(w, "CSV is empty", http.StatusBadRequest)
		return
	}

	// 4. Create Job in Postgres
	jobID := uuid.New().String()
	ctx := r.Context()

	// We insert the job with status 'pending'
	query := `INSERT INTO jobs (id, status, total_count, created_at) VALUES ($1, 'pending', $2, $3)`
	_, err = store.DB.Exec(ctx, query, jobID, len(emails), time.Now())
	if err != nil {
		fmt.Printf("DB Error: %v\n", err)
		http.Error(w, "Failed to create job", http.StatusInternalServerError)
		return
	}

	// 5. Return Success
	w.Header().Set("Content-Type", "application/json")
	resp := UploadResponse{
		JobID:     jobID,
		TotalRows: len(emails),
		Message:   "Job created successfully. Processing started.",
	}
	json.NewEncoder(w).Encode(resp)
}
