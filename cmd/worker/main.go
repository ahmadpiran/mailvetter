package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"mailvetter/internal/cache"
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
	smtpProxyEnabled := false

	if proxyListRaw != "" {
		proxies := strings.Split(proxyListRaw, ",")

		proxyLimitStr := os.Getenv("PROXY_CONCURRENCY")
		proxyLimit, err := strconv.Atoi(proxyLimitStr)
		if err != nil || proxyLimit <= 0 {
			log.Printf("⚠️  PROXY_CONCURRENCY not set or invalid (%q), defaulting to 0 (proxy.Init will apply its own default)", proxyLimitStr)
			proxyLimit = 0
		}

		smtpProxyStr := strings.ToLower(os.Getenv("SMTP_PROXY_ENABLED"))
		smtpProxyEnabled = smtpProxyStr == "true" || smtpProxyStr == "1"

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

	// 4. Determine Worker Concurrency
	concurrencyStr := os.Getenv("WORKER_CONCURRENCY")
	var concurrency int

	if c, err := strconv.Atoi(concurrencyStr); err == nil && c > 0 {
		concurrency = c
		log.Printf("🔧 WORKER_CONCURRENCY explicitly set to %d", concurrency)
	} else {
		if proxyListRaw != "" && smtpProxyEnabled {
			actualProxyLimit := cap(proxy.Semaphore)
			concurrency = actualProxyLimit * 2
			if concurrency < 10 {
				concurrency = 10
			}
			log.Printf("🧠 Auto-tuning WORKER_CONCURRENCY to %d to match proxy constraints", concurrency)
		} else {
			concurrency = 50
			log.Printf("🧠 Auto-tuning WORKER_CONCURRENCY to %d (Direct SMTP Mode)", concurrency)
		}
	}

	// 5. Build the root context. Cancelling it on shutdown propagates cleanly
	// into the worker pool and the cache cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 6. Start background cache eviction.
	// The 5-minute interval is shorter than the shortest TTL (15 min) so
	// entries are swept promptly after they expire without the goroutine
	// running so frequently that it causes contention on the write lock.
	cache.StartCleanup(ctx, 5*time.Minute)
	log.Println("✅ Cache eviction goroutine started (interval: 5m)")

	// 7. Register for SIGTERM / SIGINT. main() is the sole receiver — see
	// the detailed comment in the issue #1 fix for why having two receivers
	// on this channel causes a deadlock.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	// 8. Start the worker pool. It blocks until all goroutines exit, which
	// happens after ctx is cancelled below.
	go worker.Start(ctx, concurrency)

	// 9. Block until the OS sends a shutdown signal.
	<-quit
	log.Println("⏳ Shutdown signal received, draining in-flight jobs...")

	// Cancelling ctx propagates into the BLPop loop (workers stop picking up
	// new jobs), into per-job contexts (in-flight probes are interrupted), and
	// into the cache cleanup goroutine (exits cleanly).
	cancel()

	const drainTimeout = 30 * time.Second
	log.Printf("⏳ Waiting up to %s for in-flight jobs to complete...", drainTimeout)
	time.Sleep(drainTimeout)

	log.Println("✅ Worker shut down cleanly.")
}
