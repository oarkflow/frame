package main

import (
	"context"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/middlewares/server/idempotency"
	"github.com/oarkflow/frame/middlewares/server/requestid"
	"github.com/oarkflow/frame/server"
)

func main() {
	srv := server.Default(server.WithHostPorts(":8081"))
	srv.Use(requestid.New())
	srv.Use(idempotency.New())
	srv.GET("/", idempotency.New(), func(c context.Context, ctx *frame.Context) {
		ctx.JSON(200, "Hello world")
	})
	srv.Spin()
}
