package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/avaargsh/agent-runtime/internal/activities"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/store/postgres"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

func main() {
	endpoint := os.Getenv("DECISION_PLUGIN_URL")
	if endpoint == "" {
		log.Fatal("DECISION_PLUGIN_URL is required")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required for Run breaker enforcement")
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelStartup()
	pool, err := pgxpool.New(startupCtx, databaseURL)
	if err != nil {
		log.Fatalf("connect Runtime PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(startupCtx); err != nil {
		log.Fatalf("ping Runtime PostgreSQL: %v", err)
	}

	store := postgres.New(pool)
	if err := store.Migrate(startupCtx); err != nil {
		log.Fatalf("migrate Runtime PostgreSQL: %v", err)
	}

	addr := os.Getenv("TEMPORAL_ADDRESS")
	if addr == "" {
		addr = "127.0.0.1:7233"
	}
	c, err := client.Dial(client.Options{HostPort: addr})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	w := worker.New(c, workflows.Queue, worker.Options{})
	w.RegisterWorkflow(workflows.Run)
	w.RegisterActivity(&activities.Activities{
		Client:       decision.Client{Endpoint: endpoint},
		Breakers:     store,
		PollInterval: 250 * time.Millisecond,
	})
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatal(err)
	}
}
