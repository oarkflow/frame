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

package secure

import (
	"context"
	"fmt"
	"github.com/sujit-baniya/frame"
	"github.com/sujit-baniya/frame/pkg/protocol"
)

// New creates an instance of the secure middleware using the specified configuration.
// router.Use(secure.N)
func New(opts ...Option) frame.HandlerFunc {
	policy := newPolicy(opts)
	return func(ctx context.Context, c *frame.Context) {
		if !policy.applyToContext(ctx, c) {
			return
		}
		c.Next(ctx)
	}
}

func newPolicy(opts []Option) *policy {
	policy := &policy{
		config: options{
			sslRedirect:           true,
			isDevelopment:         false,
			stsSeconds:            315360000,
			frameDeny:             true,
			contentTypeNosniff:    true,
			browserXssFilter:      true,
			contentSecurityPolicy: "",
			ieNoOpen:              true,
			sslProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
		},
	}
	policy.fixedHeaders = &protocol.ResponseHeader{}
	policy.config.Apply(opts)
	// Frame Options header.
	if len(policy.config.customFrameOptionsValue) > 0 {
		policy.addHeader("X-Frame-Options", policy.config.customFrameOptionsValue)
	} else if policy.config.frameDeny {
		policy.addHeader("X-Frame-Options", "DENY")
	} else {
		policy.addHeader("X-Frame-Options", "SAMEORIGIN")
	}

	// Content Type Options header.
	if policy.config.contentTypeNosniff {
		policy.addHeader("X-Content-Type-Options", "nosniff")
	}

	// XSS Protection header.
	if policy.config.browserXssFilter {
		policy.addHeader("X-Xss-Protection", "1; mode=block")
	}

	// Content Security Policy header.
	if len(policy.config.contentSecurityPolicy) > 0 {
		if policy.config.contentSecurityPolicyReport {
			policy.addHeader("Content-Security-Policy-Report-Only", policy.config.contentSecurityPolicy)
		} else {
			policy.addHeader("Content-Security-Policy", policy.config.contentSecurityPolicy)
		}
	}

	if len(policy.config.referrerPolicy) > 0 {
		policy.addHeader("Referrer-Policy", policy.config.referrerPolicy)
	}

	if len(policy.config.permissionPolicy) > 0 {
		policy.addHeader("Permissions-Policy", policy.config.permissionPolicy)
	}

	// Strict Transport Security header.
	if policy.config.stsSeconds != 0 {
		stsSub := ""
		if policy.config.stsIncludeSubdomains {
			stsSub = "; includeSubdomains"
		}

		policy.addHeader(
			"Strict-Transport-Security",
			fmt.Sprintf("max-age=%d%s", policy.config.stsSeconds, stsSub))
	}

	// X-Download-Options header.
	if policy.config.ieNoOpen {
		policy.addHeader("X-Download-Options", "noopen")
	}

	// featurePolicy header.
	if len(policy.config.featurePolicy) > 0 {
		policy.addHeader("Feature-Policy", policy.config.featurePolicy)
	}
	return policy
}
