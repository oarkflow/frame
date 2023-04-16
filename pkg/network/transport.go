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

package network

import (
	"context"
	"net"
)

type Transporter interface {
	Listener() net.Listener
	// Close the transporter immediately
	Close() error

	// Shutdown is for graceful shutdown of transporter
	Shutdown(ctx context.Context) error

	// ListenAndServe start to listen and ready to accept connection
	ListenAndServe(onData OnData) error
}

// TransporterExt is the extended interface of Transporter
type TransporterExt interface {
	// Listener returns the listener of the transporter
	Listener() net.Listener
	// SetListener sets the listener of the transporter, SetListener should be called before ListenAndServe
	// If the listener is set, the transporter will use the listener to accept connection
	SetListener(l net.Listener)
}

// OnData Callback when data is ready on the connection
type OnData func(ctx context.Context, conn interface{}) error
