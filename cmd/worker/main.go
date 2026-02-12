package main

import (
	"log"
	"os"

	"mailvetter/internal/queue"
	"mailvetter/internal/store"
	"mailvetter/internal/worker"
)

func main() {
	log.Println("🚀 Starting Mailvetter Worker...")

	// 1. Initialize Redis
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	if err := queue.Init(redisAddr); err != nil {
		log.Fatalf("❌ Failed to connect to Redis: %v", err)
	}
	log.Println("✅ Connected to Redis")

	// 2. Initialize Database
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("❌ DB_URL environment variable is required")
	}
	if err := store.Init(dbURL); err != nil {
		log.Fatalf("❌ Failed to connect to DB: %v", err)
	}
	log.Println("✅ Connected to PostgreSQL")

	// 3. Start the Processing Loop
	worker.Start()
}
