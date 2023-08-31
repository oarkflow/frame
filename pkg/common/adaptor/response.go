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

package adaptor

import (
	"bufio"
	"io"
	"net"
	"net/http"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/protocol"
	"github.com/oarkflow/frame/pkg/protocol/consts"
)

type compatResponse struct {
	h           http.Header
	w           io.Writer
	r           io.Reader
	conn        net.Conn
	resp        *protocol.Response
	writeHeader bool
}

func (w *compatResponse) Header() http.Header {
	if w.h != nil {
		return w.h
	}
	w.h = make(map[string][]string)
	return w.h
}

func (w *compatResponse) WriteHeader(statusCode int) {
	if !w.writeHeader {
		for k, v := range w.h {
			for _, vv := range v {
				if k == consts.HeaderContentLength {
					continue
				}
				if k == consts.HeaderSetCookie {
					cookie := protocol.AcquireCookie()
					cookie.Parse(vv)
					w.resp.Header.SetCookie(cookie)
					continue
				}
				w.resp.Header.Add(k, vv)
			}
		}
		w.writeHeader = true
	}

	w.resp.Header.SetStatusCode(statusCode)
}

// GetCompatResponseWriter only support basic function of ResponseWriter, not for all.
func GetCompatResponseWriter(ctx *frame.Context) http.ResponseWriter {
	return &compatResponse{w: ctx.Response.BodyWriter(), r: ctx.RequestBodyStream(), conn: ctx.GetConn(), resp: ctx.GetResponse()}
}

func (w *compatResponse) Write(p []byte) (int, error) {
	if !w.writeHeader {
		w.WriteHeader(consts.StatusOK)
	}

	return w.resp.BodyWriter().Write(p)
}

func (w *compatResponse) Flush() {}

func (w *compatResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, &bufio.ReadWriter{Reader: bufio.NewReader(w.r), Writer: bufio.NewWriter(w.w)}, nil
}
