package session

import (
	"encoding/gob"
	"strings"
	"time"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/storage"
	"github.com/oarkflow/frame/pkg/common/xid"
)

// Config defines the store for middleware.
type Config struct {
	// Allowed session duration
	// Optional. Default value 24 * time.Hour
	Expiration time.Duration

	// Storage interface to store the session data
	// Optional. Default value memory.New()
	Storage storage.Storage

	// KeyLookup is a string in the form of "<source>:<name>" that is used
	// to extract session id from the request.
	// Possible values: "header:<name>", "query:<name>" or "cookie:<name>"
	// Optional. Default value "cookie:session_id".
	KeyLookup string

	// Domain of the CSRF cookie.
	// Optional. Default value "".
	CookieDomain string

	// Path of the CSRF cookie.
	// Optional. Default value "".
	CookiePath string

	// Indicates if CSRF cookie is secure.
	// Optional. Default value false.
	CookieSecure bool

	// Indicates if CSRF cookie is HTTP only.
	// Optional. Default value false.
	CookieHTTPOnly bool

	// Value of SameSite cookie.
	// Optional. Default value "Lax".
	CookieSameSite string

	ErrorHandler func(ctx *frame.Context, err error)

	// KeyGenerator generates the session key.
	// Optional. Default value utils.UUIDv4
	KeyGenerator func() string

	RegisteredObjects []any

	// Deprecated: Please use KeyLookup
	CookieName string

	// Source defines where to obtain the session id
	source Source

	// The session name
	sessionName string
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
