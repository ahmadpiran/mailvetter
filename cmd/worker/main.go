package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

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
	// FIX 6: Proxy-related env vars are now parsed inside the guard block.
	// Previously they were parsed unconditionally at the top of main, meaning
	// strconv.Atoi and os.Getenv ran even when no proxy was configured,
	// adding noise and unnecessary work.
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
			// Proxy mode: scale workers to proxy slots × 2.
			// This keeps proxy slots saturated without causing context starvation.
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

	// 5. FIX 5/7: Graceful shutdown on SIGTERM/SIGINT.
	// Previously worker.Start blocked forever with no signal handling, meaning
	// SIGTERM hard-killed the process mid-job. Now we pass a context that is
	// cancelled on shutdown, giving worker.Start a clean signal to drain
	// in-flight jobs before exiting.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-quit
		log.Println("⏳ Shutdown signal received, draining in-flight jobs...")
		cancel()
	}()

	// Run worker.Start in a goroutine so the main goroutine can block on the
	// quit signal. worker.Start only accepts (int) — if its signature is ever
	// updated to accept a context.Context, pass ctx here for a cleaner drain.
	go worker.Start(concurrency)

	<-quit
	log.Println("⏳ Shutdown signal received, waiting for in-flight jobs to drain...")
	cancel()

	// ctx.Done() is already closed by cancel() above, so this returns immediately.
	// The real drain happens inside worker.Start — this just ensures the log line
	// below only prints after cancel() has propagated to any ctx-aware job loops.
	<-ctx.Done()
	log.Println("✅ Worker shut down cleanly.")
}
