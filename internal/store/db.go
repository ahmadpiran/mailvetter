package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

// Init connects to Postgres and runs migrations
func Init(connString string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	DB, err = pgxpool.New(ctx, connString)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %w", err)
	}

	// Verify connection
	if err := DB.Ping(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return runMigrations(ctx)
}

// runMigrations creates the necessary tables if they don't exist
func runMigrations(ctx context.Context) error {
	// Table: jobs (Tracks bulk upload batches)
	queryJobs := `
	CREATE TABLE IF NOT EXISTS jobs (
		id TEXT PRIMARY KEY,
		status TEXT NOT NULL,
		total_count INT DEFAULT 0,
		processed_count INT DEFAULT 0,
		created_at TIMESTAMP DEFAULT NOW(),
		completed_at TIMESTAMP
	);`

	// Table: results (Stores individual email verification data)
	// We store the full JSON result so we can re-analyze later if needed.
	queryResults := `
	CREATE TABLE IF NOT EXISTS results (
		id SERIAL PRIMARY KEY,
		job_id TEXT NOT NULL REFERENCES jobs(id),
		email TEXT NOT NULL,
		score INT NOT NULL,
		data JSONB NOT NULL
	);`

	if _, err := DB.Exec(ctx, queryJobs); err != nil {
		return fmt.Errorf("migration failed (jobs): %w", err)
	}
	if _, err := DB.Exec(ctx, queryResults); err != nil {
		return fmt.Errorf("migration failed (results): %w", err)
	}

	return nil
}
