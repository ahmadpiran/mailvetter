package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"mailvetter/internal/queue"
	"mailvetter/internal/store"
	"mailvetter/internal/validator"
)

// Start launches a pool of worker goroutines.
func Start(concurrency int) {
	log.Printf("👷 Starting Worker Pool with %d concurrent routines...", concurrency)
	var wg sync.WaitGroup

	for i := 1; i <= concurrency; i++ {
		wg.Add(1)

		// Launch a concurrent worker
		go func(workerID int) {
			defer wg.Done()
			ctx := context.Background()

			for {
				// 1. Blocking Pop from Redis
				result, err := queue.Client.BLPop(ctx, 0*time.Second, queue.QueueName).Result()
				if err != nil {
					time.Sleep(1 * time.Second)
					continue
				}

				// 2. Parse Task
				rawJSON := result[1]
				var task queue.Task
				if err := json.Unmarshal([]byte(rawJSON), &task); err != nil {
					log.Printf("[Worker %d] ❌ Malformed task: %s\n", workerID, rawJSON)
					continue
				}

				// 3. PROCESS
				valCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
				parts, _ := validator.VerifyEmail(valCtx, task.Email, extractDomain(task.Email))
				cancel()

				// 4. SAVE to PostgreSQL
				resultJSON, _ := json.Marshal(parts)

				tx, err := store.DB.Begin(ctx)
				if err != nil {
					log.Printf("[Worker %d] DB Transaction error: %v\n", workerID, err)
					continue
				}

				_, err = tx.Exec(ctx, `
					INSERT INTO results (job_id, email, score, data)
					VALUES ($1, $2, $3, $4)
				`, task.JobID, task.Email, parts.Score, resultJSON)

				if err != nil {
					log.Printf("[Worker %d] Failed to save result: %v\n", workerID, err)
					tx.Rollback(ctx)
					continue
				}

				// Increment progress
				_, err = tx.Exec(ctx, `
					UPDATE jobs 
					SET processed_count = processed_count + 1,
					    status = CASE WHEN processed_count + 1 >= total_count THEN 'completed' ELSE status END,
						completed_at = CASE WHEN processed_count + 1 >= total_count THEN NOW() ELSE completed_at END
					WHERE id = $1
				`, task.JobID)

				if err != nil {
					log.Printf("[Worker %d] Failed to update job: %v\n", workerID, err)
					tx.Rollback(ctx)
					continue
				}

				if err := tx.Commit(ctx); err != nil {
					log.Printf("[Worker %d] Failed to commit: %v\n", workerID, err)
				} else {
					fmt.Printf("[Worker %d] ✅ Processed: %s (Score: %d)\n", workerID, task.Email, parts.Score)
				}
			}
		}(i)
	}

	// Block the main thread forever while the workers run
	wg.Wait()
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
