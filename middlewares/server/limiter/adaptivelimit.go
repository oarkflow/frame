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

package limiter

import (
	"context"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/protocol/consts"
)

// New CPU sampling algorithm using BBR
func New(opts ...Option) frame.HandlerFunc {
	limiter := NewLimiter(opts...)
	return func(c context.Context, ctx *frame.Context) {
		done, err := limiter.Allow()
		if err != nil {
			ctx.AbortWithError(consts.StatusTooManyRequests, err)
			ctx.String(consts.StatusTooManyRequests, ctx.Errors.String())
		} else {
			ctx.Next(c)
			done()
		}
	}
}
