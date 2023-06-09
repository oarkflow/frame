package etag

import (
	"bytes"
	"context"
	"hash/crc32"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/bytebufferpool"
	"github.com/oarkflow/frame/pkg/protocol/consts"
)

var (
	normalizedHeaderETag = []byte("Etag")
	weakPrefix           = []byte("W/")
)

// New creates a new middleware handler
func New(config ...Config) frame.HandlerFunc {
	// Set default config
	cfg := configDefault(config...)

	crc32q := crc32.MakeTable(0xD5828281)

	// Return new handler
	return func(ctx context.Context, c *frame.Context) {
		// Don't execute middleware if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			c.Next(ctx)
		}

		// Return err if next handler returns one
		c.Next(ctx)

		// Don't generate ETags for invalid responses
		if c.Response.StatusCode() != consts.StatusOK {
			return
		}
		body := c.Response.Body()
		// Skips ETag if no response body is present
		if len(body) == 0 {
			return
		}
		// Skip ETag if header is already present
		if c.Response.Header.Get(string(normalizedHeaderETag)) != "" {
			return
		}

		// Generate ETag for response
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)

		// Enable weak tag
		if cfg.Weak {
			_, _ = bb.Write(weakPrefix)
		}

		_ = bb.WriteByte('"')
		bb.B = appendUint(bb.Bytes(), uint32(len(body)))
		_ = bb.WriteByte('-')
		bb.B = appendUint(bb.Bytes(), crc32.Checksum(body, crc32q))
		_ = bb.WriteByte('"')

		etag := bb.Bytes()

		// Get ETag header from request
		clientEtag := c.Request.Header.Peek(consts.HeaderIfNoneMatch)

		// Check if client's ETag is weak
		if bytes.HasPrefix(clientEtag, weakPrefix) {
			// Check if server's ETag is weak
			if bytes.Equal(clientEtag[2:], etag) || bytes.Equal(clientEtag[2:], etag[2:]) {
				// W/1 == 1 || W/1 == W/1
				c.Reset()
				c.Status(consts.StatusNotModified)
				return
			}
			// W/1 != W/2 || W/1 != 2
			c.Response.Header.SetCanonical(normalizedHeaderETag, etag)

			return
		}

		if bytes.Contains(clientEtag, etag) {
			// 1 == 1
			c.Reset()
			c.Status(consts.StatusNotModified)
			return
		}
		// 1 != 2
		c.Response.Header.SetCanonical(normalizedHeaderETag, etag)

		return
	}
}

// appendUint appends n to dst and returns the extended dst.
func appendUint(dst []byte, n uint32) []byte {
	var b [20]byte
	buf := b[:]
	i := len(buf)
	var q uint32
	for n >= 10 {
		i--
		q = n / 10
		buf[i] = '0' + byte(n-q*10)
		n = q
	}
	i--
	buf[i] = '0' + byte(n)

	dst = append(dst, buf[i:]...)
	return dst
}
