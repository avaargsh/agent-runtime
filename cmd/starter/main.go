package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/avaargsh/agent-runtime/internal/decision"
	"github.com/avaargsh/agent-runtime/internal/workflows"
	"go.temporal.io/sdk/client"
)

func main() {
	addr := os.Getenv("TEMPORAL_ADDRESS")
	if addr == "" {
		addr = "127.0.0.1:7233"
	}
	c, err := client.Dial(client.Options{HostPort: addr})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	turn := decision.Turn{
		ProtocolVersion: "v0.1",
		InvocationID:    "demo-inv-1",
		TenantID:        "demo",
		AgentID:         "demo-agent",
		RunID:           "demo-run-1",
		TurnID:          "demo-turn-1",
		UserInput:       "hello",
	}
	workflowID, err := workflows.WorkflowID(turn.RunID)
	if err != nil {
		log.Fatal(err)
	}
	we, err := c.ExecuteWorkflow(context.Background(), client.StartWorkflowOptions{
		ID: workflowID, TaskQueue: workflows.Queue,
	}, workflows.Run, turn)
	if err != nil {
		log.Fatal(err)
	}
	var result decision.Result
	if err := we.Get(context.Background(), &result); err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Text)
}
