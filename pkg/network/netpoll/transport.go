// Copyright 2022 Frame Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//go:build !windows
// +build !windows

package netpoll

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/cloudwego/netpoll"
	"github.com/oarkflow/log"

	"github.com/oarkflow/frame/internal/utils"
	"github.com/oarkflow/frame/pkg/common/config"
	"github.com/oarkflow/frame/pkg/network"
)

const ctxCancelKey = "ctxCancelKey"

func cancelContext(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	ctx = context.WithValue(ctx, ctxCancelKey, cancel)
	return ctx
}

type transporter struct {
	sync.RWMutex
	senseClientDisconnection bool
	network                  string
	addr                     string
	keepAliveTimeout         time.Duration
	readTimeout              time.Duration
	writeTimeout             time.Duration
	listener                 net.Listener
	eventLoop                netpoll.EventLoop
	listenConfig             *net.ListenConfig
	OnAccept                 func(conn net.Conn) context.Context
	OnConnect                func(ctx context.Context, conn network.Conn) context.Context
	OnDisconnect             func(ctx context.Context, conn network.Conn)
}

// For transporter switch
func NewTransporter(options *config.Options) network.Transporter {
	return &transporter{
		senseClientDisconnection: options.SenseClientDisconnection,
		network:                  options.Network,
		addr:                     options.Addr,
		keepAliveTimeout:         options.KeepAliveTimeout,
		readTimeout:              options.ReadTimeout,
		writeTimeout:             options.WriteTimeout,
		listener:                 nil,
		eventLoop:                nil,
		listenConfig:             options.ListenConfig,
		OnAccept:                 options.OnAccept,
		OnConnect:                options.OnConnect,
	}
}

func (t *transporter) Listener() net.Listener {
	return t.listener
}

func (t *transporter) SetListener(l net.Listener) {
	t.listener = l
}

// ListenAndServe binds listen address and keep serving, until an error occurs
// or the transport shutdowns
func (t *transporter) ListenAndServe(onReq network.OnData) (err error) {
	network.UnlinkUdsFile(t.network, t.addr) //nolint:errcheck

	if t.listener == nil {
		if t.listenConfig != nil {
			t.listener, err = t.listenConfig.Listen(context.Background(), t.network, t.addr)
		} else {
			t.listener, err = net.Listen(t.network, t.addr)
		}
	}

	if err != nil {
		panic("create netpoll listener fail: " + err.Error())
	}

	// Initialize custom option for EventLoop
	opts := []netpoll.Option{
		netpoll.WithIdleTimeout(t.keepAliveTimeout),
		netpoll.WithOnPrepare(func(conn netpoll.Connection) context.Context {
			conn.SetReadTimeout(t.readTimeout) // nolint:errcheck
			if t.writeTimeout > 0 {
				conn.SetWriteTimeout(t.writeTimeout)
			}
			ctx := context.Background()
			if t.OnAccept != nil {
				ctx = t.OnAccept(newConn(conn))
			}
			if t.senseClientDisconnection {
				ctx = cancelContext(ctx)
			}
			return ctx
		}),
	}
	if t.OnConnect != nil {
		opts = append(opts, netpoll.WithOnConnect(func(ctx context.Context, conn netpoll.Connection) context.Context {
			return t.OnConnect(ctx, newConn(conn))
		}))
	}

	const ctxKey = "ctxKey"
	if t.senseClientDisconnection {
		opts = append(opts, netpoll.WithOnConnect(func(ctx context.Context, connection netpoll.Connection) context.Context {
			ctx, cancel := context.WithCancel(ctx)
			return context.WithValue(ctx, ctxKey, cancel)
		}),
			// Enable this when netpoll has OnDisconnect option
			netpoll.WithOnDisconnect(func(ctx context.Context, connection netpoll.Connection) {
				cancelFunc, _ := ctx.Value(ctxKey).(context.CancelFunc)
				if cancelFunc != nil {
					cancelFunc()
				}
			}),
		)
	}

	// Create EventLoop
	t.Lock()
	t.eventLoop, err = netpoll.NewEventLoop(func(ctx context.Context, connection netpoll.Connection) error {
		return onReq(ctx, newConn(connection))
	}, opts...)
	t.Unlock()
	if err != nil {
		panic("create netpoll event-loop fail")
	}

	// Start Server
	log.Info().Str("log_service", "HTTP Server").
		Str("address", utils.GetURLFromAddr(t.listener.Addr().String())).
		Str("status", "listening").
		Msg("Server started")
	t.RLock()
	err = t.eventLoop.Serve(t.listener)
	t.RUnlock()
	if err != nil {
		panic("netpoll server exit")
	}

	return nil
}

// Close forces transport to close immediately (no wait timeout)
func (t *transporter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	return t.Shutdown(ctx)
}

// Shutdown will trigger listener stop and graceful shutdown
// It will wait all connections close until reaching context.Deadline()
func (t *transporter) Shutdown(ctx context.Context) error {
	defer func() {
		network.UnlinkUdsFile(t.network, t.addr) //nolint:errcheck
		t.RUnlock()
	}()
	t.RLock()
	if t.eventLoop == nil {
		return nil
	}
	return t.eventLoop.Shutdown(ctx)
}
