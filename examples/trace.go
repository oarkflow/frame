package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func initTracing() *otlptrace.Exporter {

	exporter, err := otlptrace.New(
		context.Background(),
		otlptracehttp.NewClient(
			otlptracehttp.WithInsecure(),
			otlptracehttp.WithEndpoint("localhost:8081"),
			otlptracehttp.WithURLPath("/otlp/v1/traces"),
		),
	)

	if err != nil {
		log.Fatalf("Failed to create exporter: %v", err)
	}

	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", "Test Service"),
			attribute.String("library.language", "go"),
		),
	)

	if err != nil {
		log.Fatalf("Could not set resources: %v", err)
	}

	otel.SetTracerProvider(
		sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(resources),
		),
	)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return exporter
}

func main() {
	exporter := initTracing()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := exporter.Shutdown(ctx); err != nil {
			log.Fatalf("failed to shutdown exporter: %v", err)
		}
	}()

	// Example function calls
	ctx := context.Background()
	_, err := MyFunction1(ctx, "abc")
	if err != nil {
		panic(err)
	}
	_, err = MyFunction2(ctx, 123, true)
	if err != nil {
		panic(err)
	}
	<-time.After(10 * time.Second)
}

// TraceFunction is a higher-order function that adds tracing to a function with any signature.
func TraceFunction(ctx context.Context, name string, fn func(ctx context.Context, args ...interface{}) (interface{}, error), args ...interface{}) (interface{}, error) {
	tr := otel.Tracer(name)
	ctx, span := tr.Start(ctx, name)
	defer span.End()
	span.SetAttributes(
		attribute.String("my_file", "test.txt"),
	)
	return fn(ctx, args...)
}

// Example functions to be traced
func MyFunction1(ctx context.Context, param1 string) (string, error) {
	fn := func(ctx context.Context, args ...interface{}) (interface{}, error) {
		param1 := args[0].(string)
		fmt.Printf("Executing MyFunction1 with param1: %s\n", param1)
		return "result from MyFunction1", nil
	}

	result, err := TraceFunction(ctx, "MyFunction1", fn, param1)
	if err != nil {
		return "", err
	}
	return result.(string), nil
}

func MyFunction2(ctx context.Context, param1 int, param2 bool) (int, error) {
	fn := func(ctx context.Context, args ...interface{}) (interface{}, error) {
		param1 := args[0].(int)
		param2 := args[1].(bool)
		fmt.Printf("Executing MyFunction2 with param1: %d and param2: %t\n", param1, param2)
		return param1 * 2, nil
	}

	result, err := TraceFunction(ctx, "MyFunction2", fn, param1, param2)
	if err != nil {
		return 0, err
	}
	return result.(int), nil
}
