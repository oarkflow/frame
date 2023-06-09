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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"math/rand"
	"net/textproto"
	"strings"
	"time"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/middlewares/server/session"
)

// New validates CSRF token.
func New(opts ...Option) frame.HandlerFunc {
	cfg := NewOptions(opts...)
	selectors := strings.Split(cfg.KeyLookup, ":")

	if len(selectors) != 2 {
		panic(errors.New("[CSRF] KeyLookup must in the form of <source>:<key>"))
	}

	if cfg.Extractor == nil {
		// By default, we extract from a header
		cfg.Extractor = CsrfFromHeader(textproto.CanonicalMIMEHeaderKey(selectors[1]))

		switch selectors[0] {
		case "form":
			cfg.Extractor = CsrfFromForm(selectors[1])
		case "query":
			cfg.Extractor = CsrfFromQuery(selectors[1])
		case "param":
			cfg.Extractor = CsrfFromParam(selectors[1])
		}
	}

	return func(ctx context.Context, c *frame.Context) {
		// Don't execute middleware if Next returns true
		if cfg.Next != nil && cfg.Next(ctx, c) {
			c.Next(ctx)
			return
		}

		c.Set(csrfSecret, cfg.Secret)

		if isIgnored(cfg.IgnoreMethods, string(c.Request.Method())) {
			c.Next(ctx)
			return
		}

		val, err := session.Get(c, csrfSalt)
		salt := val.(string)
		if err != nil {
			c.Error(errMissingSalt)
			cfg.ErrorFunc(ctx, c)
			return
		}

		token, err := cfg.Extractor(ctx, c)
		if err != nil {
			c.Error(err)
			cfg.ErrorFunc(ctx, c)
			return
		}

		if tokenize(cfg.Secret, salt) != token {
			c.Error(errInvalidToken)
			cfg.ErrorFunc(ctx, c)
			return
		}

		c.Next(ctx)
	}
}

// GetToken returns a CSRF token.
func GetToken(c *frame.Context) string {
	secret := c.MustGet(csrfSecret).(string)

	if t, ok := c.Get(csrfToken); ok {
		return t.(string)
	}

	val, err := session.Get(c, csrfSalt)
	salt := val.(string)
	if err != nil {
		salt = randStr(16)
		session.Set(c, csrfSalt, salt)
		session.Save(c)
	}
	token := tokenize(secret, salt)
	c.Set(csrfToken, token)

	return token
}

// tokenize generates token through secret and salt.
func tokenize(secret, salt string) string {
	h := sha256.New()
	io.WriteString(h, salt+"-"+secret)
	hash := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return hash
}

// isIgnored determines whether the method is ignored.
func isIgnored(arr []string, value string) bool {
	ignore := false

	for _, v := range arr {
		if v == value {
			ignore = true
			break
		}
	}

	return ignore
}

var src = rand.NewSource(time.Now().UnixNano())

// randStr generates random string.
func randStr(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A rand.Int63() generates 63 random bits, enough for letterIdMax letters
	for i, cache, remain := n-1, src.Int63(), letterIdMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdMax
		}
		if idx := int(cache & letterIdMask); idx < len(letters) {
			sb.WriteByte(letters[idx])
			i--
		}
		cache >>= letterIdBits
		remain--
	}
	return sb.String()
}
