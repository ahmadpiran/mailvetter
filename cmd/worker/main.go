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

	// 5. Build a cancellable root context that is passed down into the worker
	// pool. This is the single authoritative shutdown signal for the process —
	// only main() calls cancel(), and it does so exactly once after receiving
	// an OS signal below.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	// 7. Start the worker pool in a background goroutine so that main() remains
	// free to block on the quit channel. worker.Start receives ctx so that it
	// can observe the cancellation signal — see internal/worker/runner.go.
	go worker.Start(ctx, concurrency)

	// 8. Block here until the operator sends SIGTERM or SIGINT (e.g. docker stop,
	// kubectl rollout, or Ctrl-C). This is now the ONLY receive on quit.
	<-quit
	log.Println("⏳ Shutdown signal received, draining in-flight jobs...")

	// Cancelling ctx propagates into every BLPop call and per-job context
	// inside the worker pool. Workers finish their current task, see ctx.Done()
	// on the next loop iteration, and exit cleanly.
	cancel()

	// Give in-flight jobs a bounded window to finish before the OS reclaims the
	// process. This should be set to your p99 job latency. The hard ceiling here
	// (30 s) is intentionally shorter than the per-job context timeout in
	// runner.go (5 min) so that a single stuck job cannot block a deployment
	// rollout indefinitely. In production, tune via an env var or flag.
	const drainTimeout = 30 * time.Second
	log.Printf("⏳ Waiting up to %s for in-flight jobs to complete...", drainTimeout)
	time.Sleep(drainTimeout)

	log.Println("✅ Worker shut down cleanly.")
}
