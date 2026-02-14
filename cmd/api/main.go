package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"mailvetter/internal/proxy"
	"mailvetter/internal/queue"
	"mailvetter/internal/store"
	"mailvetter/internal/validator"
)

func main() {
	// 1. Initialize Redis
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379" // Fallback for local testing outside docker
	}

	fmt.Printf("🔌 Connecting to Redis at %s...\n", redisAddr)
	if err := queue.Init(redisAddr); err != nil {
		log.Fatalf("❌ Failed to connect to Redis: %v", err)
	}
	fmt.Println("✅ Connected to Redis Queue")

	// 2. Initialize Database (NEW)
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		// Default for local testing if env is missing
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
		if err := proxy.Init(proxies); err != nil {
			log.Fatalf("❌ Failed to initialize proxy manager: %v", err)
		}
		fmt.Printf("🛡️  Proxy rotation enabled (%d proxies loaded)\n", len(proxies))
	} else {
		fmt.Println("⚠️  No proxies configured. Running with direct connections.")
	}

	// 4. Define Handlers
	http.HandleFunc("/verify", enableCORS(verifyHandler))
	http.HandleFunc("/upload", enableCORS(uploadHandler))
	http.HandleFunc("/status", enableCORS(statusHandler))
	http.HandleFunc("/results", enableCORS(resultsHandler))
	http.HandleFunc("/info", enableCORS(infoHandler))
	http.HandleFunc("/", homeHandler)

	// 5. Server Configuration
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  30 * time.Second, // Allow enough time for deep probes
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Println("🚀 Mailvetter Engine v3.0 (Production) running on :8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// Middleware to enable CORS for frontend access
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // Allow any domain (Change for Prod)
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
	// Pass context from request (handles cancellation if client disconnects)
	result, err := validator.VerifyEmail(r.Context(), email, domain)
	duration := time.Since(start)
	result.Duration = duration.String()

	if err != nil {
		result.Error = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		fmt.Printf("Error encoding response: %v\n", err)
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
	json.NewEncoder(w).Encode(guide)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<h1>Mailvetter Engine v3.0</h1><p>Active. Query /verify?email=...</p>`))
}
