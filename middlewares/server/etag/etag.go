package etag

import (
	"bytes"
	"context"
	"hash/crc32"
	"unsafe"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/bytebufferpool"
	"github.com/oarkflow/frame/pkg/protocol/consts"
)

const HeaderIfNoneMatch = "If-None-Match"

// New will create an etag middleware
func New(opts ...Option) frame.HandlerFunc {
	options := newOptions(opts...)

	var (
		headerETag = []byte("Etag")
		weakPrefix = []byte("W/")
	)

	return func(ctx context.Context, c *frame.Context) {
		c.Next(ctx)

		// skip etag if next returns true
		if options.next != nil && options.next(ctx, c) {
			c.Next(ctx)
			return
		}
		if c.Response.StatusCode() != consts.StatusOK {
			return
		}
		respBody := c.Response.Body()
		if len(respBody) == 0 {
			return
		}
		if c.Response.Header.Peek(b2s(headerETag)) != nil {
			return
		}

		// build etag
		var etag []byte
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		if options.generator != nil {
			// custom generation
			// e.g. W/your-custom-etag
			if options.weak {
				_, _ = bb.Write(weakPrefix)
			}
			_, _ = bb.Write(options.generator(ctx, c))
			etag = bb.Bytes()
		} else {
			// default generation
			// e.g. W/"11-222957957"
			if options.weak {
				_, _ = bb.Write(weakPrefix)
			}
			_ = bb.WriteByte('"')
			bb.B = appendUint(bb.Bytes(), uint32(len(respBody)))
			_ = bb.WriteByte('-')
			bb.B = appendUint(bb.Bytes(), crc32.ChecksumIEEE(respBody))
			_ = bb.WriteByte('"')
			etag = bb.Bytes()
		}

		// verify etag
		clientETag := c.Request.Header.Peek(HeaderIfNoneMatch)
		if bytes.HasPrefix(clientETag, weakPrefix) {
			// client - server
			// W/0 == 0 || W/0 == W/0
			if bytes.Equal(clientETag[2:], etag) || bytes.Equal(clientETag[2:], etag[2:]) {
				c.NotModified()
				return
			}
			// W/0 != W/1 || W/0 != 1
			c.Response.Header.SetCanonical(headerETag, etag)
			return
		}
		if bytes.Contains(clientETag, etag) {
			// 0 == 0
			c.NotModified()
			return
		}
		// 0 != 1
		c.Response.Header.SetCanonical(headerETag, etag)
	}
}

// b2s converts byte slice to a string without memory allocation
func b2s(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// appendUint appends n to dst and returns the extended dst
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
