package session

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/utils"
	"github.com/oarkflow/frame/pkg/protocol"
)

type Session struct {
	id         string         // session id
	fresh      bool           // if new session
	ctx        *frame.Context // fiber context
	store      *Store         // store configuration
	data       *data          // key value data
	byteBuffer *bytes.Buffer  // byte buffer for the en- and decode
	exp        time.Duration  // expiration of this session
}

var sessionPool = sync.Pool{
	New: func() interface{} {
		return new(Session)
	},
}

func acquireSession() *Session {
	s := sessionPool.Get().(*Session) //nolint:forcetypeassert,errcheck // We store nothing else in the pool
	if s.data == nil {
		s.data = acquireData()
	}
	if s.byteBuffer == nil {
		s.byteBuffer = new(bytes.Buffer)
	}
	s.fresh = true
	return s
}

func releaseSession(s *Session) {
	s.id = ""
	s.exp = 0
	s.ctx = nil
	s.store = nil
	if s.data != nil {
		s.data.Reset()
	}
	if s.byteBuffer != nil {
		s.byteBuffer.Reset()
	}
	sessionPool.Put(s)
}

// Fresh is true if the current session is new
func (s *Session) Fresh() bool {
	return s.fresh
}

// ID returns the session id
func (s *Session) ID() string {
	return s.id
}

// Get will return the value
func (s *Session) Get(key string) interface{} {
	// Better safe than sorry
	if s.data == nil {
		return nil
	}
	return s.data.Get(key)
}

// Set will update or create a new key value
func (s *Session) Set(key string, val interface{}) {
	// Better safe than sorry
	if s.data == nil {
		return
	}
	s.data.Set(key, val)
}

// Delete will delete the value
func (s *Session) Delete(key string) {
	// Better safe than sorry
	if s.data == nil {
		return
	}
	s.data.Delete(key)
}

// Destroy will delete the session from Storage and expire session cookie
func (s *Session) Destroy() error {
	// Better safe than sorry
	if s.data == nil {
		return nil
	}

	// Reset local data
	s.data.Reset()

	// Use external Storage if exist
	if err := s.store.Storage.Delete(s.id); err != nil {
		return err
	}

	// Expire session
	s.delSession()
	return nil
}

// Regenerate generates a new session id and delete the old one from Storage
func (s *Session) Regenerate() error {
	// Delete old id from storage
	if err := s.store.Storage.Delete(s.id); err != nil {
		return err
	}

	// Generate a new session, and set session.fresh to true
	s.refresh()

	return nil
}

// refresh generates a new session, and set session.fresh to be true
func (s *Session) refresh() {
	// Create a new id
	s.id = s.store.KeyGenerator()

	// We assign a new id to the session, so the session must be fresh
	s.fresh = true
}

// Save will update the storage and client cookie
func (s *Session) Save() error {
	// Better safe than sorry
	if s.data == nil {
		return nil
	}

	// Check if session has your own expiration, otherwise use default value
	if s.exp <= 0 {
		s.exp = s.store.Expiration
	}

	// Update client cookie
	s.setSession()

	// Convert data to bytes
	mux.Lock()
	defer mux.Unlock()
	encCache := gob.NewEncoder(s.byteBuffer)
	err := encCache.Encode(&s.data.Data)
	if err != nil {
		return fmt.Errorf("failed to encode data: %w", err)
	}

	// copy the data in buffer
	encodedBytes := make([]byte, s.byteBuffer.Len())
	copy(encodedBytes, s.byteBuffer.Bytes())

	// pass copied bytes with session id to provider
	if err := s.store.Storage.Set(s.id, encodedBytes, s.exp); err != nil {
		return err
	}

	// Release session
	// TODO: It's not safe to use the Session after called Save()
	releaseSession(s)

	return nil
}

// Keys will retrieve all keys in current session
func (s *Session) Keys() []string {
	if s.data == nil {
		return []string{}
	}
	return s.data.Keys()
}

// SetExpiry sets a specific expiration for this session
func (s *Session) SetExpiry(exp time.Duration) {
	s.exp = exp
}

func (s *Session) setSession() {
	if s.store.source == SourceHeader {
		s.ctx.Header(s.store.sessionName, s.id)
	}
	var sameSite protocol.CookieSameSite
	switch utils.ToLower(s.store.CookieSameSite) {
	case "strict":
		sameSite = protocol.CookieSameSiteStrictMode
	case "none":
		sameSite = protocol.CookieSameSiteNoneMode
	default:
		sameSite = protocol.CookieSameSiteLaxMode
	}
	s.ctx.SetCookie(s.store.sessionName, s.id, int(s.exp.Seconds()), s.store.CookiePath, s.store.CookieDomain, sameSite, s.store.CookieSecure, s.store.CookieHTTPOnly, false)
}

func (s *Session) delSession() {
	if s.store.source == SourceHeader {
		s.ctx.Request.Header.DelBytes([]byte(s.store.sessionName))
		s.ctx.Response.Header.DelBytes([]byte(s.store.sessionName))
	}
	s.ctx.Request.Header.DelCookie(s.store.sessionName)
	s.ctx.Response.Header.DelCookie(s.store.sessionName)
	var sameSite protocol.CookieSameSite
	switch utils.ToLower(s.store.CookieSameSite) {
	case "strict":
		sameSite = protocol.CookieSameSiteStrictMode
	case "none":
		sameSite = protocol.CookieSameSiteNoneMode
	default:
		sameSite = protocol.CookieSameSiteLaxMode
	}
	s.ctx.SetCookie(s.store.sessionName, "", -1, s.store.CookiePath, s.store.CookieDomain, sameSite, s.store.CookieSecure, s.store.CookieHTTPOnly, false)
}
