package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var Client *redis.Client

// Init connects to Redis and pings it to ensure it's alive.
func Init(addr string) error {
	Client = redis.NewClient(&redis.Options{
		Addr:        addr,
		Password:    "", // No password for local docker
		DB:          0,  // Default DB
		DialTimeout: 5 * time.Second,
	})

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := Client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	return nil
}
