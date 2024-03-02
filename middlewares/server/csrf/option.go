// MIT License
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

package csrf

import (
	"context"
	"errors"

	"github.com/oarkflow/frame"
)

// Option is the only struct that can be used to set Options.
type Option struct {
	F func(o *Options)
}

const (
	csrfSecret     = "csrfSecret"
	csrfSalt       = "csrfSalt"
	csrfToken      = "csrfToken"
	csrfHeaderName = "X-CSRF-TOKEN"

	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// 6 bits to represent a letter index
	letterIdBits = 6
	// All 1-bits as many as letterIdBits
	letterIdMask = 1<<letterIdBits - 1
	letterIdMax  = 63 / letterIdBits
)

var (
	errMissingHeader = errors.New("[CSRF] missing csrf token in header")
	errMissingQuery  = errors.New("[CSRF] missing csrf token in query")
	errMissingParam  = errors.New("[CSRF] missing csrf token in param")
	errMissingForm   = errors.New("[CSRF] missing csrf token in form")
	errMissingSalt   = errors.New("[CSRF] missing salt")
	errInvalidToken  = errors.New("[CSRF] invalid token")
)

type CsrfNextHandler func(ctx context.Context, c *frame.Context) bool

type CsrfExtractorHandler func(ctx context.Context, c *frame.Context) (string, error)

// Options defines the config for middleware.
type Options struct {
	Next          CsrfNextHandler
	ErrorFunc     frame.HandlerFunc
	Extractor     CsrfExtractorHandler
	Secret        string
	KeyLookup     string
	IgnoreMethods []string
}

func (o *Options) Apply(opts []Option) {
	for _, op := range opts {
		op.F(o)
	}
}

// OptionsDefault is the default options.
var OptionsDefault = Options{
	Secret: csrfSecret,
	// Assume that anything not defined as 'safe' by RFC7231 needs protection
	IgnoreMethods: []string{"GET", "HEAD", "OPTIONS", "TRACE"},
	Next:          nil,
	KeyLookup:     "header:" + csrfHeaderName,
	ErrorFunc:     func(ctx context.Context, c *frame.Context) { panic(c.Errors.Last()) },
}

func NewOptions(opts ...Option) *Options {
	options := &Options{
		Secret:        OptionsDefault.Secret,
		IgnoreMethods: OptionsDefault.IgnoreMethods,
		Next:          OptionsDefault.Next,
		KeyLookup:     OptionsDefault.KeyLookup,
		ErrorFunc:     OptionsDefault.ErrorFunc,
	}
	options.Apply(opts)
	return options
}

// WithSecret sets secret.
func WithSecret(secret string) Option {
	return Option{
		F: func(o *Options) {
			o.Secret = secret
		},
	}
}

// WithIgnoredMethods sets methods that do not need to be protected.
func WithIgnoredMethods(methods []string) Option {
	return Option{
		F: func(o *Options) {
			o.IgnoreMethods = methods
		},
	}
}

// WithNext sets whether to skip this middleware.
func WithNext(f CsrfNextHandler) Option {
	return Option{
		F: func(o *Options) {
			o.Next = f
		},
	}
}

// WithKeyLookUp sets a string in the form of "<source>:<key>" that is used
// to create an Extractor that extracts the token from the request.
func WithKeyLookUp(lookup string) Option {
	return Option{
		F: func(o *Options) {
			o.KeyLookup = lookup
		},
	}
}

// WithErrorFunc sets ErrorFunc.
func WithErrorFunc(f frame.HandlerFunc) Option {
	return Option{
		F: func(o *Options) {
			o.ErrorFunc = f
		},
	}
}

// WithExtractor sets extractor.
func WithExtractor(f CsrfExtractorHandler) Option {
	return Option{
		F: func(o *Options) {
			o.Extractor = f
		},
	}
}
