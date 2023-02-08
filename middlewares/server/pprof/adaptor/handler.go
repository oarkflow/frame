// The MIT License (MIT)
//
// Copyright (c) 2015-present Aliaksandr Valialkin, VertaMedia, Kirill Danshin, Erik Dubbelboer, FastHTTP Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// This file may have been modified by Frame authors. All Frame
// Modifications are Copyright 2022 Frame Authors.

package adaptor

import (
	"context"
	"github.com/sujit-baniya/frame"
	"github.com/sujit-baniya/frame/pkg/common/adaptor"
	"github.com/sujit-baniya/frame/pkg/protocol/consts"
	"github.com/sujit-baniya/log"
	"net/http"
	"unsafe"
)

// NewFrameHTTPHandlerFunc wraps net/http handler to frame app.HandlerFunc,
// so it can be passed to frame server
//
// While this function may be used for easy switching from net/http to frame,
// it has the following drawbacks comparing to using manually written frame
// request handler:
//
//   - A lot of useful functionality provided by frame is missing
//     from net/http handler.
//
//   - net/http -> frame handler conversion has some overhead,
//     so the returned handler will be always slower than manually written
//     frame handler.
//
// So it is advisable using this function only for net/http -> frame switching.
// Then manually convert net/http handlers to frame handlers
func NewFrameHTTPHandlerFunc(h http.HandlerFunc) frame.HandlerFunc {
	return NewFrameHTTPHandler(h)
}

// NewFrameHTTPHandler wraps net/http handler to frame app.HandlerFunc,
// so it can be passed to frame server
//
// While this function may be used for easy switching from net/http to frame,
// it has the following drawbacks comparing to using manually written frame
// request handler:
//
//   - A lot of useful functionality provided by frame is missing
//     from net/http handler.
//
//   - net/http -> frame handler conversion has some overhead,
//     so the returned handler will be always slower than manually written
//     frame handler.
//
// So it is advisable using this function only for net/http -> frame switching.
// Then manually convert net/http handlers to frame handlers
func NewFrameHTTPHandler(h http.Handler) frame.HandlerFunc {
	return func(ctx context.Context, c *frame.Context) {
		req, err := adaptor.GetCompatRequest(c.GetRequest())
		if err != nil {
			log.Error().Str("log_service", "HTTP Server").Err(err).Msg("Server Error: Get request error")
			c.String(http.StatusInternalServerError, consts.StatusMessage(http.StatusInternalServerError))
			return
		}
		req.RequestURI = b2s(c.Request.RequestURI())
		rw := adaptor.GetCompatResponseWriter(&c.Response)
		c.ForEachKey(func(k string, v interface{}) {
			ctx = context.WithValue(ctx, k, v)
		})
		h.ServeHTTP(rw, req.WithContext(ctx))
		body := c.Response.Body()
		// From net/http.ResponseWriter.Write:
		// If the Header does not contain a Content-Type line, Write adds a Content-Type set
		// to the result of passing the initial 512 bytes of written data to DetectContentType.
		if len(c.GetHeader(consts.HeaderContentType)) == 0 {
			l := 512
			if len(body) < 512 {
				l = len(body)
			}
			c.Response.Header.Set(consts.HeaderContentType, http.DetectContentType(body[:l]))
		}
	}
}

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
//
// Note it may break if string and/or slice header will change
// in the future go versions.
func b2s(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
