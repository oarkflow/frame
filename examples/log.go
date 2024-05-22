package main

import (
	"context"

	"github.com/oarkflow/log"

	"github.com/oarkflow/frame"
	logMiddleware "github.com/oarkflow/frame/middlewares/server/log"
	"github.com/oarkflow/frame/middlewares/server/requestid"
	"github.com/oarkflow/frame/middlewares/server/throttle"
	"github.com/oarkflow/frame/pkg/common/utils"
	"github.com/oarkflow/frame/pkg/protocol/consts"
	"github.com/oarkflow/frame/server"
)

func main() {
	srv := server.Default()
	srv.Use(requestid.New())
	srv.Use(logMiddleware.New(logMiddleware.Config{
		Logger: &log.DefaultLogger,
	}))
	cfg := throttle.Config{
		KeyGenerator: func(f *frame.Context) string {
			return f.ClientIP()
		},
		LimitReached: func(c context.Context, ctx *frame.Context) {
			ctx.AbortWithJSON(200, utils.H{
				"success": false,
				"code":    consts.StatusTooManyRequests,
				"message": "Too many attempts. Please try again later",
			})
		},
	}
	srv.GET("/login", throttle.New(cfg), func(c context.Context, ctx *frame.Context) {
		ctx.JSON(200, "I'm logged in")
	})
	srv.Spin()
}
