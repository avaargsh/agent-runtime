package main

import (
	"strings"
	"testing"
)

func TestValidateStartupConfig(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		databaseURL string
		wantError   string
	}{
		{
			name:      "requires Decision endpoint before checking database",
			wantError: "DECISION_PLUGIN_URL is required",
		},
		{
			name:        "rejects invalid Decision endpoint before checking database",
			endpoint:    "http://example.com",
			wantError:   "DECISION_PLUGIN_URL: plaintext decision endpoint must be loopback",
		},
		{
			name:        "rejects malformed Decision endpoint before checking database",
			endpoint:    "file:///tmp/decision",
			wantError:   "DECISION_PLUGIN_URL: invalid decision endpoint",
		},
		{
			name:        "requires database after valid Decision endpoint",
			endpoint:    "https://decision.example.com/v1/decision-turns",
			wantError:   "DATABASE_URL is required for Run breaker enforcement",
		},
		{
			name:        "accepts HTTPS endpoint and database configuration",
			endpoint:    "https://decision.example.com/v1/decision-turns",
			databaseURL: "postgres://localhost/agent_runtime",
		},
		{
			name:        "accepts loopback HTTP endpoint for development",
			endpoint:    "http://127.0.0.1:8081/v1/decision-turns",
			databaseURL: "postgres://localhost/agent_runtime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStartupConfig(tt.endpoint, tt.databaseURL)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validateStartupConfig() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateStartupConfig() error = %v, want substring %q", err, tt.wantError)
			}
		})
	}
}
