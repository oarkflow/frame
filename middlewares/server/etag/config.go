package etag

import "github.com/oarkflow/frame"

// Config defines the config for middleware.
type Config struct {
	Next func(c *frame.Context) bool
	Weak bool
}

// ConfigDefault is the default config
var ConfigDefault = Config{
	Weak: false,
	Next: nil,
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	// Return default config if nothing provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	// Set default values

	return cfg
}
