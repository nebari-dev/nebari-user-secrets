// Package telemetry sets up OpenTelemetry tracing from the environment.
package telemetry

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const serviceName = "nebari-user-secrets"

// Setup installs a global tracer provider. OTEL_EXPORTER selects the exporter:
// none (default), otlp (endpoint from OTEL_ENDPOINT, default localhost:4317,
// plaintext gRPC) or console. The returned shutdown flushes pending spans.
func Setup(ctx context.Context) (func(context.Context) error, error) {
	ctx, span := otel.Tracer(serviceName).Start(ctx, "telemetry.Setup")
	defer span.End()

	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(serviceName)))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("telemetry resource: %w", err)
	}
	opts := []sdktrace.TracerProviderOption{sdktrace.WithResource(res)}

	var exp sdktrace.SpanExporter
	switch kind := os.Getenv("OTEL_EXPORTER"); kind {
	case "", "none":
	case "console":
		exp, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
	case "otlp":
		endpoint := os.Getenv("OTEL_ENDPOINT")
		if endpoint == "" {
			endpoint = "localhost:4317"
		}
		exp, err = otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(endpoint), otlptracegrpc.WithInsecure())
	default:
		err = fmt.Errorf("unknown OTEL_EXPORTER %q (want none, otlp or console)", kind)
	}
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("telemetry exporter: %w", err)
	}
	if exp != nil {
		opts = append(opts, sdktrace.WithBatcher(exp))
	}
	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}
