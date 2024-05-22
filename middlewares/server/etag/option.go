package etag

import (
	"context"

	"github.com/oarkflow/frame"
)

type Option func(o *Options)

type Options struct {
	weak      bool
	next      NextFunc
	generator Generator
}

type (
	NextFunc  func(ctx context.Context, c *frame.Context) bool
	Generator func(ctx context.Context, c *frame.Context) []byte
)

var defaultOptions = Options{
	weak:      false,
	next:      nil,
	generator: nil,
}

func newOptions(opts ...Option) *Options {
	options := &Options{
		weak:      defaultOptions.weak,
		next:      defaultOptions.next,
		generator: defaultOptions.generator,
	}
	options.apply(opts)
	return options
}

func (o *Options) apply(opts []Option) {
	for _, opt := range opts {
		opt(o)
	}
}

// WithWeak will add weak prefix to the front of etag
func WithWeak() Option {
	return func(o *Options) {
		o.weak = true
	}
}

// WithNext will skip etag middleware when return is true
func WithNext(next NextFunc) Option {
	return func(o *Options) {
		o.next = next
	}
}

// WithGenerator will replace default etag generation with yours
// Note: you should not add a weak prefix to your custom etag when used with WithWeak
func WithGenerator(gen Generator) Option {
	return func(o *Options) {
		o.generator = gen
	}
}
