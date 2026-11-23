package telemetry

import (
	"context"
	"testing"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		wantErr bool
	}{
		{"default none", "", false},
		{"none", "none", false},
		{"console", "console", false},
		{"otlp", "otlp", false}, // the exporter does not dial at construction
		{"unknown", "zipkin", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER", tc.env)
			shutdown, err := Setup(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil {
				if err := shutdown(context.Background()); err != nil {
					t.Fatalf("shutdown: %v", err)
				}
			}
		})
	}
}
