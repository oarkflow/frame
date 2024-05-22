package session

import (
	"encoding/gob"
	"strings"
	"time"

	"github.com/oarkflow/xid"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/storage"
)

// Config defines the store for middleware.
type Config struct {
	Storage           storage.Storage
	ErrorHandler      func(ctx *frame.Context, err error)
	KeyGenerator      func() string
	CookieDomain      string
	CookiePath        string
	CookieSameSite    string
	KeyLookup         string
	CookieName        string
	source            Source
	sessionName       string
	RegisteredObjects []any
	Expiration        time.Duration
	CookieSecure      bool
	CookieHTTPOnly    bool
}

type Source string

const (
	SourceCookie   Source = "cookie"
	SourceHeader   Source = "header"
	SourceURLQuery Source = "query"
)

// ConfigDefault is the default store
var ConfigDefault = Config{
	Expiration: 24 * time.Hour,
	KeyLookup:  "cookie:session_id",
	KeyGenerator: func() string {
		return xid.New().String()
	},
	source:      "cookie",
	sessionName: "session_id",
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	// Return default store if nothing provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default store
	cfg := config[0]

	// Set default values
	if int(cfg.Expiration.Seconds()) <= 0 {
		cfg.Expiration = ConfigDefault.Expiration
	}
	if cfg.KeyLookup == "" {
		cfg.KeyLookup = ConfigDefault.KeyLookup
	}
	if cfg.KeyGenerator == nil {
		cfg.KeyGenerator = ConfigDefault.KeyGenerator
	}

	if len(cfg.RegisteredObjects) > 0 {
		for _, obj := range cfg.RegisteredObjects {
			gob.Register(obj)
		}
	}
	selectors := strings.Split(cfg.KeyLookup, ":")
	const numSelectors = 2
	if len(selectors) != numSelectors {
		panic("[session] KeyLookup must in the form of <source>:<name>")
	}
	switch Source(selectors[0]) {
	case SourceCookie:
		cfg.source = SourceCookie
	case SourceHeader:
		cfg.source = SourceHeader
	case SourceURLQuery:
		cfg.source = SourceURLQuery
	default:
		panic("[session] source is not supported")
	}
	cfg.sessionName = selectors[1]

	return cfg
}
