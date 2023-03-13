package throttle

import "github.com/sujit-baniya/frame"

const (
	// X-RateLimit-* headers
	xRateLimitLimit     = "X-RateLimit-Limit"
	xRateLimitRemaining = "X-RateLimit-Remaining"
	xRateLimitReset     = "X-RateLimit-Reset"
)

type LimiterHandler interface {
	New(config Config) frame.HandlerFunc
}

// New creates a new middleware handler
func New(config ...Config) frame.HandlerFunc {
	// Set default config
	cfg := configDefault(config...)

	// Return the specified middleware handler.
	return cfg.LimiterMiddleware.New(cfg)
}
