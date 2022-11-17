/*
 * Copyright 2022 CloudWeGo Authors
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

package tracer

import (
	"context"
	"github.com/sujit-baniya/frame"
)

// Tracer is executed at the start and finish of an HTTP.
type Tracer interface {
	Start(ctx context.Context, c *frame.Context) context.Context
	Finish(ctx context.Context, c *frame.Context)
}

type Controller interface {
	Append(col Tracer)
	DoStart(ctx context.Context, c *frame.Context) context.Context
	DoFinish(ctx context.Context, c *frame.Context, err error)
	HasTracer() bool
}
