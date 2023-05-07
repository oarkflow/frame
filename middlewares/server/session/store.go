package session

import (
	"encoding/gob"
	"fmt"
	"sync"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/storage/memory"
	"github.com/oarkflow/frame/pkg/common/utils"
	"github.com/oarkflow/frame/pkg/protocol"
)

type Store struct {
	Config
}

var mux sync.Mutex

func New(config ...Config) *Store {
	// Set default store
	cfg := configDefault(config...)

	if cfg.Storage == nil {
		cfg.Storage = memory.New()
	}

	return &Store{
		cfg,
	}
}

// RegisterType will allow you to encode/decode custom types
// into any Storage provider
func (*Store) RegisterType(i interface{}) {
	gob.Register(i)
}

// Get will get/create a session
func (s *Store) Get(c *frame.Context, errorHandler ...func(ctx *frame.Context, err error)) (*Session, error) {
	var fresh bool
	loadData := true

	id := s.getSessionID(c)
	if len(id) == 0 {
		fresh = true
		var err error
		if id, err = s.responseCookies(c); err != nil {
			return nil, err
		}
	}

	// If no key exist, create new one
	if len(id) == 0 {
		loadData = false
		id = s.KeyGenerator()
	}

	// Create session object
	sess := acquireSession()
	sess.ctx = c
	sess.store = s
	sess.id = id
	sess.fresh = fresh

	// Fetch existing data
	if loadData {
		raw, err := s.Storage.Get(id)
		// Unmarshal if we found data
		if raw != nil && err == nil {
			mux.Lock()
			defer mux.Unlock()
			_, _ = sess.byteBuffer.Write(raw) //nolint:errcheck // This will never fail
			encCache := gob.NewDecoder(sess.byteBuffer)
			err := encCache.Decode(&sess.data.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to decode session data: %w", err)
			}
		} else if err != nil {
			if len(errorHandler) > 0 {
				errorHandler[0](c, err)
				sess.fresh = true
			} else {
				return nil, err
			}
		} else {
			// both raw and err is nil, which means id is not in the storage
			sess.fresh = true
		}
	}

	return sess, nil
}

// getSessionID will return the session id from:
// 1. cookie
// 2. http headers
// 3. query string
func (s *Store) getSessionID(c *frame.Context) string {
	id := c.Cookie(s.sessionName)
	if len(id) > 0 {
		return utils.CopyString(string(id))
	}

	if s.source == SourceHeader {
		id = c.Request.Header.Peek(s.sessionName)
		if len(id) > 0 {
			return string(id)
		}
	}

	if s.source == SourceURLQuery {
		id = []byte(c.Query(s.sessionName))
		if len(id) > 0 {
			return utils.CopyString(string(id))
		}
	}

	return ""
}

func (s *Store) responseCookies(c *frame.Context) (string, error) {
	// Get key from response cookie
	cookieValue := c.Cookie(s.sessionName)
	if len(cookieValue) == 0 {
		return "", nil
	}

	cookie := protocol.AcquireCookie()
	defer protocol.ReleaseCookie(cookie)
	err := cookie.ParseBytes(cookieValue)
	if err != nil {
		return "", err
	}

	value := make([]byte, len(cookie.Value()))
	copy(value, cookie.Value())
	id := string(value)
	return id, nil
}

// Reset will delete all session from the storage
func (s *Store) Reset() error {
	return s.Storage.Reset()
}
