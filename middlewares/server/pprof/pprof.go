// The MIT License (MIT)
//
// Copyright (c) 2016 Bo-Yi Wu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// This file may have been modified by Frame authors. All Frame
// Modifications are Copyright 2022 Frame Authors.

package pprof

import (
	"github.com/sujit-baniya/frame/middlewares/server/pprof/adaptor"
	"github.com/sujit-baniya/frame/pkg/route"
	"github.com/sujit-baniya/frame/server"
	"net/http/pprof"
)

const (
	// DefaultPrefix url prefix of pprof
	DefaultPrefix = "/debug/pprof"
)

func getPrefix(prefixOptions ...string) string {
	prefix := DefaultPrefix
	if len(prefixOptions) > 0 {
		prefix = prefixOptions[0]
	}
	return prefix
}

// Register the standard HandlerFuncs from the net/http/pprof package with
// the provided hertz.Hertz. prefixOptions is a optional. If not prefixOptions,
// the default path prefix is used, otherwise first prefixOptions will be path prefix.
func Register(r *server.Frame, prefixOptions ...string) {
	RouteRegister(&(r.RouterGroup), prefixOptions...)
}

// RouteRegister the standard HandlerFuncs from the net/http/pprof package with
// the provided hertz.RouterGroup. prefixOptions is a optional. If not prefixOptions,
// the default path prefix is used, otherwise first prefixOptions will be path prefix.
func RouteRegister(rg *route.RouterGroup, prefixOptions ...string) {
	prefix := getPrefix(prefixOptions...)

	prefixRouter := rg.Group(prefix)
	{
		prefixRouter.GET("/", adaptor.NewFrameHTTPHandlerFunc(pprof.Index))
		prefixRouter.GET("/cmdline", adaptor.NewFrameHTTPHandlerFunc(pprof.Cmdline))

		prefixRouter.GET("/profile", adaptor.NewFrameHTTPHandlerFunc(pprof.Profile))
		prefixRouter.POST("/symbol", adaptor.NewFrameHTTPHandlerFunc(pprof.Symbol))
		prefixRouter.GET("/symbol", adaptor.NewFrameHTTPHandlerFunc(pprof.Symbol))
		prefixRouter.GET("/trace", adaptor.NewFrameHTTPHandlerFunc(pprof.Trace))
		prefixRouter.GET("/allocs", adaptor.NewFrameHTTPHandlerFunc(pprof.Handler("allocs").ServeHTTP))
		prefixRouter.GET("/block", adaptor.NewFrameHTTPHandlerFunc(pprof.Handler("block").ServeHTTP))
		prefixRouter.GET("/goroutine", adaptor.NewFrameHTTPHandlerFunc(pprof.Handler("goroutine").ServeHTTP))
		prefixRouter.GET("/heap", adaptor.NewFrameHTTPHandlerFunc(pprof.Handler("heap").ServeHTTP))
		prefixRouter.GET("/mutex", adaptor.NewFrameHTTPHandlerFunc(pprof.Handler("mutex").ServeHTTP))
		prefixRouter.GET("/threadcreate", adaptor.NewFrameHTTPHandlerFunc(pprof.Handler("threadcreate").ServeHTTP))
	}
}
