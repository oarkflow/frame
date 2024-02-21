package idempotency

import (
	"context"
	"fmt"
	"strings"

	"github.com/oarkflow/log"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/internal/bytesconv"
	"github.com/oarkflow/frame/pkg/common/utils"
)

// Inspired by https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header-02
// and https://github.com/penguin-statistics/backend-next/blob/f2f7d5ba54fc8a58f168d153baa17b2ad4a14e45/internal/pkg/middlewares/idempotency.go

const (
	localsKeyIsFromCache   = "idempotency_isfromcache"
	localsKeyWasPutToCache = "idempotency_wasputtocache"
)

func IsFromCache(c *frame.Context) bool {
	val, exists := c.Get(localsKeyIsFromCache)
	if exists {
		return true
	}
	return val != nil
}

func WasPutToCache(c *frame.Context) bool {
	val, exists := c.Get(localsKeyWasPutToCache)
	if exists {
		return true
	}
	return val != nil
}

func New(config ...Config) frame.HandlerFunc {
	// Set default config
	cfg := configDefault(config...)

	keepResponseHeadersMap := make(map[string]struct{}, len(cfg.KeepResponseHeaders))
	for _, h := range cfg.KeepResponseHeaders {
		keepResponseHeadersMap[strings.ToLower(h)] = struct{}{}
	}

	maybeWriteCachedResponse := func(c *frame.Context, key string) (bool, error) {
		if val, err := cfg.Storage.Get(key); err != nil {
			return false, fmt.Errorf("failed to read response: %w", err)
		} else if val != nil {
			var res response
			if _, err := res.UnmarshalMsg(val); err != nil {
				return false, fmt.Errorf("failed to unmarshal response: %w", err)
			}
			c.SetStatusCode(res.StatusCode)

			for header, vals := range res.Headers {
				for _, val := range vals {
					c.Header(header, val)
				}
			}

			if len(res.Body) != 0 {
				if _, err := c.Write(res.Body); err != nil {
					return true, err
				}
			}

			c.Set(localsKeyIsFromCache, true)

			return true, nil
		}

		return false, nil
	}

	return func(ctx context.Context, c *frame.Context) {
		// Don't execute middleware if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			fmt.Println("Coming here")
			c.Next(ctx)
		}
		fmt.Println(string(c.Path()))
		// Don't execute middleware if the idempotency key is empty
		val, _ := c.Get(cfg.KeyHeader)
		key := utils.CopyString(fmt.Sprintf("%v", val))
		if key == "" {
			c.Next(ctx)
		}
		fmt.Println("Hello")
		// Validate key
		if err := cfg.KeyHeaderValidate(key); err != nil {
			c.AbortWithError(500, err)
			return
		}

		// First-pass: if the idempotency key is in the storage, get and return the response
		if ok, err := maybeWriteCachedResponse(c, key); err != nil {
			c.AbortWithError(500, fmt.Errorf("failed to write cached response at fastpath: %w", err))
			return
		} else if ok {
			return
		}

		if err := cfg.Lock.Lock(key); err != nil {
			c.AbortWithError(500, fmt.Errorf("failed to lock: %w", err))
			return
		}
		defer func() {
			if err := cfg.Lock.Unlock(key); err != nil {
				log.Error().Msgf("[IDEMPOTENCY] failed to unlock key %q: %v", key, err)
			}
		}()

		// Lock acquired. If the idempotency key now is in the storage, get and return the response
		if ok, err := maybeWriteCachedResponse(c, key); err != nil {
			c.AbortWithError(500, fmt.Errorf("failed to write cached response while locked: %w", err))
			return
		} else if ok {
			return
		}

		c.Next(ctx)

		// Construct response
		res := &response{
			StatusCode: c.Response.StatusCode(),

			Body: utils.CopyBytes(c.Response.Body()),
		}
		{
			headers := make(map[string][]string)
			c.VisitAllHeaders(func(key, value []byte) {
				k := bytesconv.B2s(key)
				headers[k] = c.Response.Header.GetAll(k)
			})
			if cfg.KeepResponseHeaders == nil {
				// Keep all
				res.Headers = headers
			} else {
				// Filter
				res.Headers = make(map[string][]string)
				for h := range headers {
					if _, ok := keepResponseHeadersMap[utils.ToLower(h)]; ok {
						res.Headers[h] = headers[h]
					}
				}
			}
		}

		// Marshal response
		bs, err := res.MarshalMsg(nil)
		if err != nil {
			c.AbortWithError(500, fmt.Errorf("failed to marshal response: %w", err))
			return
		}

		// Store response
		if err := cfg.Storage.Set(key, bs, cfg.Lifetime); err != nil {
			c.AbortWithError(500, fmt.Errorf("failed to save response: %w", err))
			return
		}

		c.Set(localsKeyWasPutToCache, true)

		return
	}
}
