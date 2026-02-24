package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"mailvetter/internal/queue"
	"mailvetter/internal/store"
	"mailvetter/internal/validator"
)

// Start launches a pool of worker goroutines and blocks until every goroutine
// has exited. The caller signals shutdown by cancelling ctx.
func Start(ctx context.Context, concurrency int) {
	log.Printf("👷 Starting Worker Pool with %d concurrent routines...", concurrency)

	var wg sync.WaitGroup

	for i := 1; i <= concurrency; i++ {
		wg.Add(1)

		go func(workerID int) {
			defer wg.Done()

			for {
				// BLPop with a short timeout instead of 0 (block forever).
				//
				// Using a non-zero timeout means the call returns periodically
				// even on an idle queue, giving us a natural checkpoint to test
				// ctx.Err() and exit the loop cleanly on shutdown.
				//
				// A 2-second timeout is a good balance: short enough that
				// shutdown feels instant to an operator, long enough that we
				// are not hammering Redis with constant re-connects on an empty
				// queue. Adjust to taste — anything under ~10 s is fine.
				result, err := queue.Client.BLPop(ctx, 2*time.Second, queue.QueueName).Result()
				if err != nil {
					// Context cancelled or deadline exceeded — this is the clean
					// shutdown path. Exit the goroutine immediately.
					if ctx.Err() != nil {
						log.Printf("[Worker %d] 🛑 Shutdown signal received, exiting.", workerID)
						return
					}

					// redis.Nil means BLPop timed out with no work available
					// (queue was empty for the full 2-second window). This is
					// completely normal — just loop and wait again.
					if errors.Is(err, queue.ErrNil) {
						continue
					}

					// Any other error (network blip, Redis restart, etc.).
					// Log it and back off briefly before retrying so we do not
					// spin-loop and flood the logs during a Redis outage.
					log.Printf("[Worker %d] ⚠️  BLPop error: %v — backing off 1s", workerID, err)
					select {
					case <-time.After(1 * time.Second):
					case <-ctx.Done():
						log.Printf("[Worker %d] 🛑 Shutdown during backoff, exiting.", workerID)
						return
					}
					continue
				}

				// BLPop returns a two-element slice: [queueName, payload].
				rawJSON := result[1]
				var task queue.Task
				if err := json.Unmarshal([]byte(rawJSON), &task); err != nil {
					log.Printf("[Worker %d] ❌ Malformed task (skipping): %s — %v", workerID, rawJSON, err)
					continue
				}

				processTask(ctx, workerID, task)
			}
		}(i)
	}

	// Block until every goroutine has returned. When ctx is cancelled, all
	// workers exit their loops (after finishing any in-flight job), wg reaches
	// zero, and this call returns — allowing main() to proceed with its exit
	// log line and then terminate the process.
	wg.Wait()
	log.Println("👷 All workers exited. Pool shut down.")
}

// processTask runs a single verification job inside a closure so that defer
// statements (cancel, tx.Rollback) have a well-defined scope that ends when
// the task is complete, not at the end of the outer goroutine loop.
func processTask(ctx context.Context, workerID int, task queue.Task) {
	// Each job gets its own 5-minute deadline. If a particular email causes
	// a probe to hang (e.g. a firewall silently dropping TCP to port 25),
	// this ceiling ensures the worker slot is recycled within a bounded time.
	//
	// Because valCtx is derived from ctx, cancelling ctx (shutdown) also
	// cancels valCtx — so in-flight jobs are interrupted promptly on shutdown
	// rather than being allowed to run out their full 5-minute window.
	valCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	parts, _ := validator.VerifyEmail(valCtx, task.Email, extractDomain(task.Email))

	resultJSON, err := json.Marshal(parts)
	if err != nil {
		log.Printf("[Worker %d] ❌ Failed to marshal result for %s: %v", workerID, task.Email, err)
		return
	}

	// Use the parent ctx (not valCtx) for the DB transaction. The verification
	// timeout should not also cut off our ability to persist the result. If ctx
	// itself is cancelled (shutdown) we accept that this write may not complete.
	tx, err := store.DB.Begin(ctx)
	if err != nil {
		log.Printf("[Worker %d] ❌ DB transaction error for %s: %v", workerID, task.Email, err)
		return
	}
	// Rollback is a no-op if Commit succeeds, so it is always safe to defer.
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO results (job_id, email, score, data)
		VALUES ($1, $2, $3, $4)
	`, task.JobID, task.Email, parts.Score, resultJSON)
	if err != nil {
		log.Printf("[Worker %d] ❌ Failed to insert result for %s: %v", workerID, task.Email, err)
		return
	}

	_, err = tx.Exec(ctx, `
		UPDATE jobs
		SET processed_count = processed_count + 1,
		    status = CASE WHEN processed_count + 1 >= total_count THEN 'completed' ELSE status END,
		    completed_at = CASE WHEN processed_count + 1 >= total_count THEN NOW() ELSE completed_at END
		WHERE id = $1
	`, task.JobID)
	if err != nil {
		log.Printf("[Worker %d] ❌ Failed to update job progress for %s: %v", workerID, task.Email, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("[Worker %d] ❌ Failed to commit for %s: %v", workerID, task.Email, err)
		return
	}

	fmt.Printf("[Worker %d] ✅ Processed: %s (Score: %d)\n", workerID, task.Email, parts.Score)
}

// extractDomain returns the domain part of an email address.
func extractDomain(email string) string {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			return email[i+1:]
		}
	}
	return ""
}
