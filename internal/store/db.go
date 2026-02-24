package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

// Init connects to Postgres and runs migrations.
func Init(connString string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	DB, err = pgxpool.New(ctx, connString)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %w", err)
	}

	if err := DB.Ping(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return runMigrations(ctx)
}

func runMigrations(ctx context.Context) error {
	// Table: jobs — tracks bulk upload batches.
	queryJobs := `
	CREATE TABLE IF NOT EXISTS jobs (
		id             TEXT      PRIMARY KEY,
		status         TEXT      NOT NULL,
		total_count    INT       DEFAULT 0,
		processed_count INT      DEFAULT 0,
		created_at     TIMESTAMP DEFAULT NOW(),
		completed_at   TIMESTAMP
	);`

	// Table: results — stores individual email verification data.
	// The full JSON result is stored so it can be re-analysed later without
	// re-running the verification probes.
	queryResults := `
	CREATE TABLE IF NOT EXISTS results (
		id      SERIAL  PRIMARY KEY,
		job_id  TEXT    NOT NULL REFERENCES jobs(id),
		email   TEXT    NOT NULL,
		score   INT     NOT NULL,
		data    JSONB   NOT NULL
	);`

	// Index 1 (critical): makes all job_id-filtered queries O(log n).
	queryIdxResultsJobID := `
	CREATE INDEX IF NOT EXISTS idx_results_job_id
		ON results (job_id);`

	// Index 2: supports status-filtered queries on the jobs table.
	queryIdxJobsStatus := `
	CREATE INDEX IF NOT EXISTS idx_jobs_status
		ON jobs (status);`

	// Index 3: composite index that satisfies both the job_id filter AND the
	// ORDER BY id ASC in the /results handler in a single index scan, avoiding
	// a separate sort step on large result sets.
	queryIdxResultsJobIDID := `
	CREATE INDEX IF NOT EXISTS idx_results_job_id_id
		ON results (job_id, id);`

	migrations := []struct {
		name  string
		query string
	}{
		{"create table jobs", queryJobs},
		{"create table results", queryResults},
		{"create index idx_results_job_id", queryIdxResultsJobID},
		{"create index idx_jobs_status", queryIdxJobsStatus},
		{"create index idx_results_job_id_id", queryIdxResultsJobIDID},
	}

	for _, m := range migrations {
		if _, err := DB.Exec(ctx, m.query); err != nil {
			return fmt.Errorf("migration failed (%s): %w", m.name, err)
		}
	}

	return nil
}
