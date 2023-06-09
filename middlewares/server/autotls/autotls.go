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

package autotls

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"

	"github.com/oarkflow/log"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/config"
	"github.com/oarkflow/frame/pkg/network/standard"
	"github.com/oarkflow/frame/server"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

type tlsContextKey string

var (
	ctxKey  = tlsContextKey("autls")
	todoCtx = context.WithValue(context.Background(), ctxKey, "done")
)

func NewTlsConfig(domains ...string) *tls.Config {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
	}
	if len(domains) > 0 {
		m.HostPolicy = autocert.HostWhitelist(domains...)
	}
	dir := cacheDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Error().Str("log_service", "HTTP Server").Err(err).Str("log_service", "HTTP Server").Msg("Server Error: autocert.NewListener not using a cache")
	} else {
		m.Cache = autocert.DirCache(dir)
	}
	return m.TLSConfig()
}

func run(ctx context.Context, tlsServer *server.Frame) error {
	var g errgroup.Group

	redirectServer := server.New(server.WithHostPorts(":http"))
	redirectServer.NoRoute(func(c context.Context, ctx *frame.Context) {
		target := "https://" + string(ctx.Request.URI().Host()) + string(ctx.Request.URI().RequestURI())

		ctx.Redirect(http.StatusMovedPermanently, []byte(target))
	})

	g.Go(func() error {
		redirectServer.Spin()
		return nil
	})
	g.Go(func() error {
		tlsServer.Spin()
		return nil
	})

	g.Go(func() error {
		if v := ctx.Value(ctxKey); v != nil {
			return nil
		}

		<-ctx.Done()

		var gShutdown errgroup.Group
		gShutdown.Go(func() error {
			return redirectServer.Shutdown(context.Background())
		})
		gShutdown.Go(func() error {
			return tlsServer.Shutdown(context.Background())
		})

		return gShutdown.Wait()
	})
	return g.Wait()
}

// RunWithContext support 1-line LetsEncrypt HTTPS servers with graceful shutdown
func RunWithContext(ctx context.Context, h *server.Frame) error {
	return run(ctx, h)
}

// Run support 1-line LetsEncrypt HTTPS servers
func Run(h *server.Frame) error {
	return run(todoCtx, h)
}

// NewServerWithManagerAndTlsConfig creates Frame server with autocert manager and TLS config
func NewServerWithManagerAndTlsConfig(m *autocert.Manager, tlsc *tls.Config, opts ...config.Option) *server.Frame {
	if m.Cache == nil {
		var e error
		m.Cache, e = getCacheDir()
		if e != nil {
			log.Error().Str("log_service", "HTTP Server").Str("log_service", "HTTP Server").Err(e).Msg("")
		}
	}

	if tlsc == nil {
		tlsc = m.TLSConfig()
	}

	defaultTLSConfig := m.TLSConfig()
	tlsc.GetCertificate = defaultTLSConfig.GetCertificate
	tlsc.NextProtos = defaultTLSConfig.NextProtos

	opts = append(opts,
		server.WithHostPorts(":https"),
		server.WithTransport(standard.NewTransporter),
		server.WithTLS(tlsc),
	)
	return server.New(opts...)
}
