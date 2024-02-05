// The MIT License (MIT)
//
// Copyright (c) 2020 Fiber
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

package keyauth

import (
	"context"
	"errors"
	"strings"

	"github.com/oarkflow/frame"

	"github.com/savsgio/gotils/strconv"
)

// ErrMissingOrMalformedAPIKey When there is no request of the key thrown ErrMissingOrMalformedAPIKey
var ErrMissingOrMalformedAPIKey = errors.New("missing or malformed API Key")

type QueryFunc func(*frame.Context) (string, error)

func New(opts ...Option) frame.HandlerFunc {
	cfg := NewOptions(opts...)
	queryFuncSlice := make([]QueryFunc, 0)
	for k, v := range cfg.keyLookAuthSchemeMap {
		parts := strings.Split(k, ":")
		if len(parts) != 2 {
			panic(errors.New("the length of parts should be equal to 2"))
		}
		queryFuncSlice = append(queryFuncSlice, getQueryFunc(parts[0], parts[1], v))
	}

	// Return middleware handler
	return func(c context.Context, ctx *frame.Context) {
		// Filter request to skip middleware
		if cfg.filterHandler != nil && cfg.filterHandler(c, ctx) {
			ctx.Next(c)
			return
		}
		var finalKey string
		var finalErr error
		for index, extractor := range queryFuncSlice {
			tempKey, tempErr := extractor(ctx)
			if tempKey != "" {
				finalKey = tempKey
				finalErr = tempErr
				break
			}
			if index == len(queryFuncSlice)-1 {
				finalKey = tempKey
				finalErr = tempErr
			}
		}
		if _, e := ctx.Get("keyauth_options"); !e {
			ctx.Set("keyauth_options", cfg)
		}
		if finalErr != nil {
			cfg.errorHandler(c, ctx, finalErr)
			return
		}
		valid, err := cfg.validator(c, ctx, finalKey)
		if err == nil && valid {
			ctx.Set(cfg.contextKey, finalKey)
			cfg.successHandler(c, ctx)
			return
		}
		cfg.errorHandler(c, ctx, err)
	}
}

func getQueryFunc(in string, key string, authScheme string) func(*frame.Context) (string, error) {
	switch in {
	case "header":
		return KeyFromHeader(key, authScheme)
	case "query":
		return KeyFromQuery(key)
	case "form":
		return KeyFromForm(key)
	case "param":
		return KeyFromParam(key)
	case "cookie":
		return KeyFromCookie(key)
	}
	panic(errors.New("invalid look up key"))
}

// KeyFromHeader returns a function that extracts api key from the request header.
func KeyFromHeader(header, authScheme string) func(*frame.Context) (string, error) {
	return func(c *frame.Context) (string, error) {
		auth := strconv.B2S(c.GetHeader(header))
		l := len(authScheme)
		if len(auth) > 0 && l == 0 {
			return auth, nil
		}
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", ErrMissingOrMalformedAPIKey
	}
}

// KeyFromQuery returns a function that extracts api key from the query string.
func KeyFromQuery(param string) func(*frame.Context) (string, error) {
	return func(c *frame.Context) (string, error) {
		key := c.Query(param)
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// KeyFromForm returns a function that extracts api key from the form.
func KeyFromForm(param string) func(*frame.Context) (string, error) {
	return func(c *frame.Context) (string, error) {
		key := strconv.B2S(c.FormValue(param))
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// KeyFromParam returns a function that extracts api key from the url param string.
func KeyFromParam(param string) func(*frame.Context) (string, error) {
	return func(c *frame.Context) (string, error) {
		key := c.Param(param)
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}

// KeyFromCookie returns a function that extracts api key from the named cookie.
func KeyFromCookie(name string) func(*frame.Context) (string, error) {
	return func(c *frame.Context) (string, error) {
		key := strconv.B2S(c.Cookie(name))
		if key == "" {
			return "", ErrMissingOrMalformedAPIKey
		}
		return key, nil
	}
}
