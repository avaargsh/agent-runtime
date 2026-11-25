package main

import (
	"errors"
	"fmt"

	"github.com/avaargsh/agent-runtime/internal/decision"
)

// validateStartupConfig validates all required configuration before the
// Worker initializes PostgreSQL or connects to Temporal.
func validateStartupConfig(endpoint, databaseURL string) error {
	if endpoint == "" {
		return errors.New("DECISION_PLUGIN_URL is required")
	}
	if err := decision.ValidateEndpoint(endpoint); err != nil {
		return fmt.Errorf("DECISION_PLUGIN_URL: %w", err)
	}
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required for Run breaker enforcement")
	}
	return nil
}
