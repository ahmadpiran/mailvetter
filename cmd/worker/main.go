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
	proxyLimitStr := os.Getenv("PROXY_CONCURRENCY")
	proxyLimit, _ := strconv.Atoi(proxyLimitStr)

	smtpProxyStr := strings.ToLower(os.Getenv("SMTP_PROXY_ENABLED"))
	smtpProxyEnabled := smtpProxyStr == "true" || smtpProxyStr == "1"

	if proxyListRaw != "" {
		proxies := strings.Split(proxyListRaw, ",")
		if err := proxy.Init(proxies, proxyLimit, smtpProxyEnabled); err != nil {
			log.Fatalf("❌ Failed to initialize proxy manager: %v", err)
		}

		log.Printf("🛡️  Proxy rotation enabled (%d proxies loaded, max %d concurrent HTTP)\n", len(proxies), cap(proxy.Semaphore))
		if smtpProxyEnabled {
			log.Println("⚠️  SMTP Proxying is ENABLED (Port 25 traffic will route through proxies)")
		} else {
			log.Println("✅ SMTP Proxying is DISABLED (Hybrid Mode: Port 25 traffic routes direct from VPS)")
		}
	} else {
		log.Println("⚠️  No proxies configured. Running with direct connections.")
	}

	// 4. Start the Processing Loop with Dynamic Auto-Tuning
	concurrencyStr := os.Getenv("WORKER_CONCURRENCY")
	var concurrency int

	if c, err := strconv.Atoi(concurrencyStr); err == nil && c > 0 {
		// User explicitly set a limit in .env, respect it
		concurrency = c
	} else {
		// Auto-Tuning Logic
		if proxyListRaw != "" && smtpProxyEnabled {
			// Proxy mode: Scale workers to Proxy Slots x 2.
			// This keeps the 5 proxy slots saturated without causing Context Starvation.
			actualProxyLimit := cap(proxy.Semaphore)
			concurrency = actualProxyLimit * 2

			// Failsafe minimum so the engine doesn't crawl
			if concurrency < 10 {
				concurrency = 10
			}
			log.Printf("🧠 Auto-tuning WORKER_CONCURRENCY to %d to match Proxy constraints", concurrency)
		} else {
			// Hybrid or Direct mode: Safe to run high concurrency
			concurrency = 50
			log.Printf("🧠 Auto-tuning WORKER_CONCURRENCY to %d (Direct SMTP Mode)", concurrency)
		}
	}

	worker.Start(concurrency)
}
