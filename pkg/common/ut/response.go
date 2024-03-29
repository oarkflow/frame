/*
 * Copyright 2022 Frame Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ut

import (
	"bytes"

	"github.com/oarkflow/frame/pkg/protocol"
	"github.com/oarkflow/frame/pkg/protocol/consts"
)

// ResponseRecorder records handler's response for later test
type ResponseRecorder struct {
	header      *protocol.ResponseHeader
	Body        *bytes.Buffer
	result      *protocol.Response
	Code        int
	Flushed     bool
	wroteHeader bool
}

// NewRecorder returns an initialized ResponseRecorder.
func NewRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		header: new(protocol.ResponseHeader),
		Body:   new(bytes.Buffer),
		Code:   consts.StatusOK,
	}
}

// Header returns the response headers to mutate within a handler.
// To test the headers that were written after a handler completes,
// use the Result method and see the returned Response value's Header.
func (rw *ResponseRecorder) Header() *protocol.ResponseHeader {
	m := rw.header
	if m == nil {
		m = new(protocol.ResponseHeader)
		rw.header = m
	}
	return m
}

// Write implements io.Writer. The data in buf is written to
// rw.Body, if not nil.
func (rw *ResponseRecorder) Write(buf []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(consts.StatusOK)
	}
	if rw.Body != nil {
		rw.Body.Write(buf)
	}
	return len(buf), nil
}

// WriteString implements io.StringWriter. The data in str is written
// to rw.Body, if not nil.
func (rw *ResponseRecorder) WriteString(str string) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(consts.StatusOK)
	}
	if rw.Body != nil {
		rw.Body.WriteString(str)
	}
	return len(str), nil
}

// WriteHeader sends an HTTP response header with the provided
// status code.
func (rw *ResponseRecorder) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	if rw.header == nil {
		rw.header = new(protocol.ResponseHeader)
	}
	rw.header.SetStatusCode(code)
	rw.Code = code
	rw.wroteHeader = true
}

// Flush implements http.Flusher. To test whether Flush was
// called, see rw.Flushed.
func (rw *ResponseRecorder) Flush() {
	if !rw.wroteHeader {
		rw.WriteHeader(consts.StatusOK)
	}
	rw.Flushed = true
}

// Result returns the response generated by the handler.
//
// The returned Response will have at least its StatusCode,
// Header, Body, and optionally Trailer populated.
// More fields may be populated in the future, so callers should
// not DeepEqual the result in tests.
//
// The Response.Header is a snapshot of the headers at the time of the
// first write call, or at the time of this call, if the handler never
// did a write.
//
// The Response.Body is guaranteed to be non-nil and Body.Read call is
// guaranteed to not return any error other than io.EOF.
//
// Result must only be called after the handler has finished running.
func (rw *ResponseRecorder) Result() *protocol.Response {
	if rw.result != nil {
		return rw.result
	}

	res := new(protocol.Response)
	h := rw.Header()
	h.CopyTo(&res.Header)
	if rw.Body != nil {
		b := rw.Body.Bytes()
		res.SetBody(b)
		res.Header.SetContentLength(len(b))
	}

	rw.result = res
	return res
}
