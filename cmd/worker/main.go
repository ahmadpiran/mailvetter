package main

import (
	"log"
	"os"
	"strconv"
	"strings"

	"mailvetter/internal/proxy"
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

	// 3. Initialize Proxy Manager
	proxyListRaw := os.Getenv("PROXY_LIST")
	if proxyListRaw != "" {
		proxies := strings.Split(proxyListRaw, ",")
		if err := proxy.Init(proxies); err != nil {
			log.Fatalf("❌ Failed to initialize proxy manager: %v", err)
		}
		log.Printf("🛡️  Proxy rotation enabled (%d proxies loaded)\n", len(proxies))
	} else {
		log.Println("⚠️  No proxies configured. Running with direct connections.")
	}

	// 4. Start the Processing Loop
	concurrencyStr := os.Getenv("WORKER_CONCURRENCY")
	concurrency := 20 // Default to 20 parallel workers

	if c, err := strconv.Atoi(concurrencyStr); err == nil && c > 0 {
		concurrency = c
	}

	worker.Start(concurrency)
}
