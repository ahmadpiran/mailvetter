package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var Client *redis.Client

// Task represents a single unit of work for the worker
type Task struct {
	JobID string `json:"job_id"`
	Email string `json:"email"`
}

const QueueName = "tasks:verify"

// Init connects to Redis
func Init(addr string) error {
	Client = redis.NewClient(&redis.Options{
		Addr:        addr,
		Password:    "",
		DB:          0,
		DialTimeout: 5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	return nil
}

// EnqueueBatch pushes a list of emails to the Redis queue in one go.
func EnqueueBatch(ctx context.Context, jobID string, emails []string) error {
	if len(emails) == 0 {
		return nil
	}

	// 1. Convert emails to JSON tasks
	var values []interface{}
	for _, email := range emails {
		task := Task{JobID: jobID, Email: email}
		data, err := json.Marshal(task)
		if err != nil {
			return err
		}
		values = append(values, data)
	}

	// 2. Push to Redis (RPUSH appends to the tail of the list)
	// We use a pipeline (implicit in go-redis for variadic args) to send all at once.
	if err := Client.RPush(ctx, QueueName, values...).Err(); err != nil {
		return fmt.Errorf("failed to enqueue tasks: %w", err)
	}

	return nil
}
