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
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-present Aliaksandr Valialkin, VertaMedia, Kirill Danshin, Erik Dubbelboer, FastHTTP Authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * This file may have been modified by Frame authors. All Frame
 * Modifications are Copyright 2022 Frame Authors.
 */

package client

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/oarkflow/frame/pkg/common/utils"

	"github.com/oarkflow/frame/internal/bytestr"
	"github.com/oarkflow/frame/pkg/common/config"
	"github.com/oarkflow/frame/pkg/common/errors"
	"github.com/oarkflow/frame/pkg/common/timer"
	"github.com/oarkflow/frame/pkg/protocol"
	"github.com/oarkflow/frame/pkg/protocol/consts"
)

const defaultMaxRedirectsCount = 16

var (
	errTimeout          = errors.New(errors.ErrTimeout, errors.ErrorTypePublic, "host client")
	errMissingLocation  = errors.NewPublic("missing Location header for http redirect")
	errTooManyRedirects = errors.NewPublic("too many redirects detected when doing the request")

	clientURLResponseChPool sync.Pool
)

type HostClient interface {
	Doer
	SetDynamicConfig(dc *DynamicConfig)
	CloseIdleConnections()
	ShouldRemove() bool
	ConnectionCount() int
}

type Response struct {
	Error      error
	Header     map[string][]byte
	Cookie     map[string][]byte
	Body       []byte
	StatusCode int
}

type Doer interface {
	Do(ctx context.Context, req *protocol.Request, resp *protocol.Response) error
}

// DefaultRetryIf Default retry condition, mainly used for idempotent requests.
// If this cannot be satisfied, you can implement your own retry condition.
func DefaultRetryIf(req *protocol.Request, resp *protocol.Response, err error) bool {
	// cannot retry if the request body is not rewindable
	if req.IsBodyStream() {
		return false
	}

	if isIdempotent(req, resp, err) {
		return true
	}
	// Retry non-idempotent requests if the server closes
	// the connection before sending the response.
	//
	// This case is possible if the server closes the idle
	// keep-alive connection on timeout.
	//
	// Apache and nginx usually do this.
	if err == io.EOF {
		return true
	}

	return false
}

func isIdempotent(req *protocol.Request, resp *protocol.Response, err error) bool {
	return req.Header.IsGet() ||
		req.Header.IsHead() ||
		req.Header.IsPut() ||
		req.Header.IsDelete() ||
		req.Header.IsOptions() ||
		req.Header.IsTrace()
}

// DynamicConfig is config set which will be confirmed when starts a request.
type DynamicConfig struct {
	ProxyURI *protocol.URI
	Addr     string
	IsTLS    bool
}

// RetryIfFunc signature of retry if function
// Judge whether to retry by request,response or error , return true is retry
type RetryIfFunc func(req *protocol.Request, resp *protocol.Response, err error) bool

type clientURLResponse struct {
	err        error
	header     map[string][]byte
	cookie     map[string][]byte
	body       []byte
	statusCode int
}

func GetURL(ctx context.Context, dst []byte, url string, c Doer, requestOptions ...config.RequestOption) (response Response) {
	req := protocol.AcquireRequest()
	req.SetOptions(requestOptions...)

	response = doRequestFollowRedirectsBuffer(ctx, req, dst, url, c)

	protocol.ReleaseRequest(req)
	return
}

func GetURLTimeout(ctx context.Context, dst []byte, url string, timeout time.Duration, c Doer, requestOptions ...config.RequestOption) (response Response) {
	deadline := time.Now().Add(timeout)
	return GetURLDeadline(ctx, dst, url, deadline, c, requestOptions...)
}

func GetURLDeadline(ctx context.Context, dst []byte, url string, deadline time.Time, c Doer, requestOptions ...config.RequestOption) (response Response) {
	timeout := -time.Since(deadline)
	if timeout <= 0 {
		response.Body = dst
		response.Error = errTimeout
		return
	}

	var ch chan clientURLResponse
	chv := clientURLResponseChPool.Get()
	if chv == nil {
		chv = make(chan clientURLResponse, 1)
	}
	ch = chv.(chan clientURLResponse)

	req := protocol.AcquireRequest()
	req.SetOptions(requestOptions...)

	// Note that the request continues execution on errTimeout until
	// client-specific ReadTimeout exceeds. This helps to limit load
	// on slow hosts by MaxConns* concurrent requests.
	//
	// Without this 'hack' the load on slow host could exceed MaxConns*
	// concurrent requests, since timed out requests on client side
	// usually continue execution on the host.
	go func() {
		rsp := doRequestFollowRedirectsBuffer(ctx, req, dst, url, c)
		ch <- clientURLResponse{
			statusCode: rsp.StatusCode,
			body:       rsp.Body,
			err:        rsp.Error,
			header:     rsp.Header,
			cookie:     rsp.Cookie,
		}
	}()

	tc := timer.AcquireTimer(timeout)
	select {
	case resp := <-ch:
		protocol.ReleaseRequest(req)
		clientURLResponseChPool.Put(chv)
		response.StatusCode = resp.statusCode
		response.Body = resp.body
		response.Error = resp.err
		response.Header = resp.header
		response.Cookie = resp.cookie
	case <-tc.C:
		response.Body = dst
		response.Error = errTimeout
	}
	timer.ReleaseTimer(tc)

	return
}

func PostURL(ctx context.Context, dst []byte, url string, postArgs *protocol.Args, c Doer, requestOptions ...config.RequestOption) (response Response) {
	req := protocol.AcquireRequest()
	req.Header.SetMethodBytes(bytestr.StrPost)
	req.Header.SetContentTypeBytes(bytestr.StrPostArgsContentType)
	req.SetOptions(requestOptions...)

	if postArgs != nil {
		if _, err := postArgs.WriteTo(req.BodyWriter()); err != nil {
			response.Error = err
			return
		}
	}

	response = doRequestFollowRedirectsBuffer(ctx, req, dst, url, c)

	protocol.ReleaseRequest(req)
	return
}

func doRequestFollowRedirectsBuffer(ctx context.Context, req *protocol.Request, dst []byte, url string, c Doer) (response Response) {
	resp := protocol.AcquireResponse()
	bodyBuf := resp.BodyBuffer()
	oldBody := bodyBuf.B
	bodyBuf.B = dst

	statusCode, _, err := DoRequestFollowRedirects(ctx, req, resp, url, defaultMaxRedirectsCount, c)
	response.StatusCode = statusCode
	response.Error = err
	// In HTTP2 scenario, client use stream mode to create a request and its body is in body stream.
	// In HTTP1, only client recv body exceed max body size and client is in stream mode can trig it.
	response.Body = resp.Body()
	bodyBuf.B = oldBody
	header := make(map[string][]byte)
	cookie := make(map[string][]byte)
	resp.Header.VisitAll(func(key, value []byte) {
		header[utils.ToString(key)] = value
	})
	resp.Header.VisitAllCookie(func(key, value []byte) {
		cookie[utils.ToString(key)] = value
	})
	response.Header = header
	response.Cookie = cookie
	protocol.ReleaseResponse(resp)

	return response
}

func DoRequestFollowRedirects(ctx context.Context, req *protocol.Request, resp *protocol.Response, url string, maxRedirectsCount int, c Doer) (statusCode int, body []byte, err error) {
	redirectsCount := 0

	for {
		req.SetRequestURI(url)
		req.ParseURI()

		if err = c.Do(ctx, req, resp); err != nil {
			break
		}
		statusCode = resp.Header.StatusCode()
		if !StatusCodeIsRedirect(statusCode) {
			break
		}

		redirectsCount++
		if redirectsCount > maxRedirectsCount {
			err = errTooManyRedirects
			break
		}
		location := resp.Header.PeekLocation()
		if len(location) == 0 {
			err = errMissingLocation
			break
		}
		url = getRedirectURL(url, location)
	}

	return statusCode, body, err
}

// StatusCodeIsRedirect returns true if the status code indicates a redirect.
func StatusCodeIsRedirect(statusCode int) bool {
	return statusCode == consts.StatusMovedPermanently ||
		statusCode == consts.StatusFound ||
		statusCode == consts.StatusSeeOther ||
		statusCode == consts.StatusTemporaryRedirect ||
		statusCode == consts.StatusPermanentRedirect
}

func getRedirectURL(baseURL string, location []byte) string {
	u := protocol.AcquireURI()
	u.Update(baseURL)
	u.UpdateBytes(location)
	redirectURL := u.String()
	protocol.ReleaseURI(u)
	return redirectURL
}

func DoTimeout(ctx context.Context, req *protocol.Request, resp *protocol.Response, timeout time.Duration, c Doer) error {
	if timeout <= 0 {
		return errTimeout
	}
	// Note: it will overwrite the reqTimeout.
	req.SetOptions(config.WithRequestTimeout(timeout))
	return c.Do(ctx, req, resp)
}

func DoDeadline(ctx context.Context, req *protocol.Request, resp *protocol.Response, deadline time.Time, c Doer) error {
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return errTimeout
	}
	// Note: it will overwrite the reqTimeout.
	req.SetOptions(config.WithRequestTimeout(timeout))
	return c.Do(ctx, req, resp)
}
