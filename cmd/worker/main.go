package main

import (
	"log"
	"os"

	"github.com/avaargsh/agent-runtime/internal/activities"
	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
)

func main() {
	endpoint := os.Getenv("DECISION_PLUGIN_URL")
	if endpoint == "" {
		log.Fatal("DECISION_PLUGIN_URL is required")
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
	w.RegisterActivity(&activities.Activities{Client: decision.Client{Endpoint: endpoint}})
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatal(err)
	}
}
