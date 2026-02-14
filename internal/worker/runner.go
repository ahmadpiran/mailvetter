package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"mailvetter/internal/queue"
	"mailvetter/internal/store"
	"mailvetter/internal/validator"
)

// Start launches the worker loop.
// It blocks forever, waiting for tasks.
func Start() {
	log.Println("👷 Worker started. Waiting for tasks...")
	ctx := context.Background()

	for {
		// 1. Blocking Pop from Redis (Waits 0s = forever until item arrives)
		// BLPOP returns: [queue_name, value]
		result, err := queue.Client.BLPop(ctx, 0*time.Second, queue.QueueName).Result()
		if err != nil {
			log.Printf("❌ Redis error: %v\n", err)
			time.Sleep(1 * time.Second) // Backoff on error
			continue
		}

		// 2. Parse the Task
		rawJSON := result[1]
		var task queue.Task
		if err := json.Unmarshal([]byte(rawJSON), &task); err != nil {
			log.Printf("❌ Malformed task: %s\n", rawJSON)
			continue
		}

		// 3. PROCESS: Run the Email Verification
		// We create a timeout context for the validation itself
		valCtx, cancel := context.WithTimeout(ctx, 60*time.Second)

		parts, _ := validator.VerifyEmail(valCtx, task.Email, extractDomain(task.Email))
		// Note: We ignore the error variable (_) because VerifyEmail handles errors internally
		// by populating parts.Error. Even if it fails, we want the 'parts' object to save to DB.

		cancel() // cleanup context

		// 4. SAVE: Write result to PostgreSQL
		// We serialize the full result to JSONB for storage
		resultJSON, _ := json.Marshal(parts)

		tx, err := store.DB.Begin(ctx)
		if err != nil {
			log.Printf("DB Transaction error: %v\n", err)
			continue
		}

		// A. Insert Record
		_, err = tx.Exec(ctx, `
			INSERT INTO results (job_id, email, score, data)
			VALUES ($1, $2, $3, $4)
		`, task.JobID, task.Email, parts.Score, resultJSON)

		if err != nil {
			log.Printf("Failed to save result: %v\n", err)
			tx.Rollback(ctx)
			continue
		}

		// B. Update Job Progress
		// We increment processed_count.
		// If processed_count matches total_count, we mark it as 'completed'.
		_, err = tx.Exec(ctx, `
			UPDATE jobs 
			SET processed_count = processed_count + 1,
			    status = CASE 
                    WHEN processed_count + 1 >= total_count THEN 'completed' 
                    ELSE status 
                END,
				completed_at = CASE 
                    WHEN processed_count + 1 >= total_count THEN NOW() 
                    ELSE completed_at 
                END
			WHERE id = $1
		`, task.JobID)

		if err != nil {
			log.Printf("Failed to update job: %v\n", err)
			tx.Rollback(ctx)
			continue
		}

		// C. Commit
		if err := tx.Commit(ctx); err != nil {
			log.Printf("Failed to commit transaction: %v\n", err)
		} else {
			fmt.Printf("✅ Processed: %s (Score: %d)\n", task.Email, parts.Score)
		}
	}
}

// Helper to get domain from email
func extractDomain(email string) string {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			return email[i+1:]
		}
	}
	return ""
}
