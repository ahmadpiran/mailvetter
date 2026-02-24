package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	"mailvetter/internal/validator"
)

func main() {
	// 1. Initialize Redis
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}
	fmt.Printf("🔌 Connecting to Redis at %s...\n", redisAddr)
	if err := queue.Init(redisAddr); err != nil {
		log.Fatalf("❌ Failed to connect to Redis: %v", err)
	}
	fmt.Println("✅ Connected to Redis Queue")

	// 2. Initialize Database
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		dbURL = "postgres://mv_user:mv_password@localhost:5432/mailvetter_db"
	}
	fmt.Println("🔌 Connecting to Database...")
	if err := store.Init(dbURL); err != nil {
		log.Fatalf("❌ Failed to connect to DB: %v", err)
	}
	fmt.Println("✅ Connected to PostgreSQL & Migrations Applied")

	// 3. Initialize Proxy Manager
	proxyListRaw := os.Getenv("PROXY_LIST")
	if proxyListRaw != "" {
		proxies := strings.Split(proxyListRaw, ",")

		proxyLimitStr := os.Getenv("PROXY_CONCURRENCY")
		proxyLimit, err := strconv.Atoi(proxyLimitStr)
		if err != nil || proxyLimit <= 0 {
			log.Printf("⚠️  PROXY_CONCURRENCY not set or invalid (%q), defaulting to 0 (proxy.Init will apply its own default)", proxyLimitStr)
			proxyLimit = 0
		}

		smtpProxyStr := strings.ToLower(os.Getenv("SMTP_PROXY_ENABLED"))
		smtpProxyEnabled := smtpProxyStr == "true" || smtpProxyStr == "1"

		if err := proxy.Init(proxies, proxyLimit, smtpProxyEnabled); err != nil {
			log.Fatalf("❌ Failed to initialize proxy manager: %v", err)
		}

		fmt.Printf("🛡️  Proxy rotation enabled (%d proxies loaded, max %d concurrent HTTP)\n", len(proxies), cap(proxy.Semaphore))
		if smtpProxyEnabled {
			fmt.Println("⚠️  SMTP Proxying is ENABLED (Port 25 traffic will route through proxies)")
		} else {
			fmt.Println("✅ SMTP Proxying is DISABLED (Hybrid Mode: Port 25 traffic routes direct from VPS)")
		}
	} else {
		fmt.Println("⚠️  No proxies configured. Running with direct connections.")
	}

	// 4. Build the root context used for background goroutines.
	// Cancelling this context on shutdown stops the cache cleanup goroutine
	// (and any other background work tied to it) cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 5. Start background cache eviction.
	// StartCleanup launches a single goroutine that calls Cleanup every 5
	// minutes and exits when ctx is cancelled (i.e. on graceful shutdown).
	cache.StartCleanup(ctx, 5*time.Minute)
	fmt.Println("✅ Cache eviction goroutine started (interval: 5m)")

	// 6. Define Handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", enableCORS(requireAPIKey(verifyHandler)))
	mux.HandleFunc("/upload", enableCORS(requireAPIKey(uploadHandler)))
	mux.HandleFunc("/status", enableCORS(requireAPIKey(statusHandler)))
	mux.HandleFunc("/results", enableCORS(requireAPIKey(resultsHandler)))
	mux.HandleFunc("/info", enableCORS(infoHandler))
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	// 7. Server Configuration
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 8. Graceful shutdown on SIGTERM / SIGINT.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		fmt.Println("🚀 Mailvetter Engine v3.0 (Production) running on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server error: %v", err)
		}
	}()

	<-quit
	fmt.Println("⏳ Shutdown signal received, draining in-flight requests...")

	// Cancelling ctx stops the cache cleanup goroutine and any other
	// background work before the process exits.
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("❌ Graceful shutdown failed: %v", err)
	}
	fmt.Println("✅ Server shut down cleanly.")
}

// enableCORS middleware sets CORS headers for frontend access.
// Note: Access-Control-Allow-Origin is set to "*" which is permissive.
// Restrict this to your specific frontend origin in production.
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "Missing 'email' parameter", http.StatusBadRequest)
		return
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "Malformed email", http.StatusBadRequest)
		return
	}
	domain := parts[1]

	start := time.Now()
	result, err := validator.VerifyEmail(r.Context(), email, domain)
	result.Duration = time.Since(start).String()

	if err != nil {
		result.Error = err.Error()
		if r.Context().Err() != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGatewayTimeout)
			json.NewEncoder(w).Encode(result)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("❌ Error encoding /verify response for %s: %v", email, err)
	}
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	guide := map[string]interface{}{
		"service": "Mailvetter Engine",
		"version": "3.0.0 (Full-Spectrum)",
		"capabilities": []string{
			"Deep SMTP (VRFY, Postmaster, Greylist)",
			"O365 Zombie Detection",
			"Catch-All Disambiguation",
			"Extended Socials (Adobe, GitHub, Gravatar)",
			"Infrastructure (SPF, DMARC, Domain Age)",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(guide); err != nil {
		log.Printf("❌ Error encoding /info response: %v", err)
	}
}
