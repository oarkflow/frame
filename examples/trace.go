package main

import (
	"context"
	"fmt"
	"reflect"

	"go.opentelemetry.io/otel"
)

// TraceDecorator is a higher-order function that adds tracing to a function with any signature.
func TraceDecorator(fn interface{}) interface{} {
	tracer := otel.Tracer("function-tracing")

	return reflect.MakeFunc(reflect.TypeOf(fn), func(args []reflect.Value) (results []reflect.Value) {
		// Start a span for the function
		ctx := context.Background() // Assuming no context is passed to the function
		ctx, span := tracer.Start(ctx, "function-execution")
		defer span.End()

		// Prepare the arguments for calling the original function
		in := make([]reflect.Value, len(args))
		for i, arg := range args {
			in[i] = arg
		}

		// Call the original function
		return reflect.ValueOf(fn).Call(in)
	}).Interface()
}

// Example functions to be traced
func myFunction1(ctx context.Context, param1 string) int {
	fmt.Printf("Executing myFunction1 with param1: %s\n", param1)
	return 0
}

func myFunction2(ctx context.Context, param1 int, param2 bool) (int, error) {
	fmt.Printf("Executing myFunction2 with param1: %d and param2: %t\n", param1, param2)
	return param1, nil
}

func main() {
	// Wrap myFunction1 with tracing
	tracedFunction1 := TraceDecorator(myFunction1).(func(context.Context, string) int)

	// Wrap myFunction2 with tracing
	tracedFunction2 := TraceDecorator(myFunction2).(func(context.Context, int, bool))

	// Call the traced functions
	tracedFunction1(context.Background(), "abc")
	tracedFunction2(context.Background(), 123, true)
}
