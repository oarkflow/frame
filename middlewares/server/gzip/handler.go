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

package gzip

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/compress"
	"github.com/oarkflow/frame/pkg/protocol"
)

type gzipHandler struct {
	*Options
	level int
}

func newGzipHandler(level int, opts ...Option) *gzipHandler {
	handler := &gzipHandler{
		Options: DefaultOptions,
		level:   level,
	}
	for _, fn := range opts {
		fn(handler.Options)
	}
	return handler
}

func (g *gzipHandler) Handle(ctx context.Context, c *frame.Context) {
	if fn := g.DecompressFn; fn != nil && c.Request.Header.Get("Content-Encoding") == "gzip" {
		fn(ctx, c)
	}
	if !g.shouldCompress(&c.Request) {
		return
	}

	c.Next(ctx)

	if len(c.Response.Body()) <= 0 {
		return
	}

	c.Header("Content-Encoding", "gzip")
	c.Header("Vary", "Accept-Encoding")
	gzipBytes := compress.AppendGzipBytesLevel(nil, c.Response.Body(), g.level)
	c.Response.SetBodyStream(bytes.NewBuffer(gzipBytes), len(gzipBytes))
}

func (g *gzipHandler) shouldCompress(req *protocol.Request) bool {
	if !strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") ||
		strings.Contains(req.Header.Get("Connection"), "Upgrade") ||
		strings.Contains(req.Header.Get("Accept"), "text/event-stream") {
		return false
	}

	path := string(req.URI().RequestURI())

	extension := filepath.Ext(path)
	if g.ExcludedExtensions.Contains(extension) {
		return false
	}

	if g.ExcludedPaths.Contains(path) {
		return false
	}
	if g.ExcludedPathRegexes.Contains(path) {
		return false
	}

	return true
}
