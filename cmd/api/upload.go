package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"mailvetter/internal/queue"
	"mailvetter/internal/store"

	"github.com/google/uuid"
)

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
		http.Error(w, "Missing 'file' parameter", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 3. Read CSV
	reader := csv.NewReader(file)
	var emails []string
	isFirstRow := true

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Invalid CSV format", http.StatusBadRequest)
			return
		}

		if len(record) > 0 {
			val := record[0]
			// Skip the row if it's the first row and looks like a header
			if isFirstRow && (val == "email" || val == "Email" || val == "Email Address") {
				isFirstRow = false
				continue
			}
			isFirstRow = false

			if val != "" {
				emails = append(emails, val)
			}
		}
	}

	// 4. Create Job in Postgres
	jobID := uuid.New().String()
	ctx := r.Context()

	query := `INSERT INTO jobs (id, status, total_count, created_at) VALUES ($1, 'pending', $2, $3)`
	_, err = store.DB.Exec(ctx, query, jobID, len(emails), time.Now())
	if err != nil {
		fmt.Printf("DB Error: %v\n", err)
		http.Error(w, "Failed to create job", http.StatusInternalServerError)
		return
	}

	// 5. Push to Redis Queue
	if err := queue.EnqueueBatch(ctx, jobID, emails); err != nil {
		fmt.Printf("Redis Error: %v\n", err)
		http.Error(w, "Failed to queue tasks", http.StatusInternalServerError)
		return
	}

	// 6. Return Success
	w.Header().Set("Content-Type", "application/json")
	resp := UploadResponse{
		JobID:     jobID,
		TotalRows: len(emails),
		Message:   "Job created and queued. Processing started.",
	}
	json.NewEncoder(w).Encode(resp)
}
