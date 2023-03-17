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

package stats

import (
	"context"
	"github.com/oarkflow/frame"
	"runtime/debug"

	"github.com/oarkflow/frame/pkg/common/tracer"
	"github.com/oarkflow/frame/pkg/common/tracer/stats"
	"github.com/oarkflow/log"
)

// Controller controls tracers.
type Controller struct {
	tracers []tracer.Tracer
}

// Append appends a new tracer to the controller.
func (ctl *Controller) Append(col tracer.Tracer) {
	ctl.tracers = append(ctl.tracers, col)
}

// DoStart starts the tracers.
func (ctl *Controller) DoStart(ctx context.Context, c *frame.Context) context.Context {
	defer ctl.tryRecover()
	Record(c.GetTraceInfo(), stats.HTTPStart, nil)

	for _, col := range ctl.tracers {
		ctx = col.Start(ctx, c)
	}
	return ctx
}

// DoFinish calls the tracers in reversed order.
func (ctl *Controller) DoFinish(ctx context.Context, c *frame.Context, err error) {
	defer ctl.tryRecover()
	Record(c.GetTraceInfo(), stats.HTTPFinish, err)
	if err != nil {
		c.GetTraceInfo().Stats().SetError(err)
	}

	// reverse the order
	for i := len(ctl.tracers) - 1; i >= 0; i-- {
		ctl.tracers[i].Finish(ctx, c)
	}
}

func (ctl *Controller) HasTracer() bool {
	return ctl != nil && len(ctl.tracers) > 0
}

func (ctl *Controller) tryRecover() {
	if err := recover(); err != nil {
		log.Warn().Str("log_service", "HTTP Server").Msgf("Panic happened during tracer call. This doesn't affect the http call, but may lead to lack of monitor data such as metrics and logs: %s, %s", err, string(debug.Stack()))
	}
}
