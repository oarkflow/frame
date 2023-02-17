package session

import (
	"encoding/gob"
	"github.com/sujit-baniya/frame/middlewares/server/session/storage/memory"
	"time"

	"github.com/sujit-baniya/frame"
	"github.com/sujit-baniya/frame/pkg/common/utils"
)

var RememberMeExpiry = 30 * 24 * time.Hour
var DefaultSessionExpiry = 30 * time.Minute

var DefaultSession = New(Config{
	Expiration:     DefaultSessionExpiry,
	KeyLookup:      "cookie:Frame-Session",
	CookieHTTPOnly: true,
	Storage:        memory.New(),
})

func Default(cfg Config) *Store {
	DefaultSession = New(cfg)
	return DefaultSession
}

func Set(c *frame.Context, key string, value interface{}, exp ...time.Duration) error {
	sess := mustPickSession(c)
	sess.Set(key, value)
	if len(exp) > 0 {
		sess.SetExpiry(exp[0])
	}
	return sess.Save()
}

func SetKeys(c *frame.Context, data utils.H, exp ...time.Duration) error {
	sess := mustPickSession(c)
	for key, value := range data {
		sess.Set(key, value)
	}
	if len(exp) > 0 {
		sess.SetExpiry(exp[0])
	}
	return sess.Save()
}

func Delete(c *frame.Context, key string) error {
	sess := mustPickSession(c)
	sess.Delete(key)
	return sess.Save()
}

func RememberMe(c *frame.Context) error {
	return SetExpiry(c, RememberMeExpiry)
}

func SetExpiry(c *frame.Context, exp time.Duration) error {
	sess := mustPickSession(c)
	sess.SetExpiry(exp)
	return sess.Save()
}

func DeleteKeys(c *frame.Context, keys ...string) error {
	sess := mustPickSession(c)
	for _, key := range keys {
		sess.Delete(key)
	}
	return sess.Save()
}

func DeleteWithDestroy(c *frame.Context, keys ...string) error {
	sess := mustPickSession(c)
	for _, key := range keys {
		sess.Delete(key)
	}
	Destroy(c)
	return sess.Save()
}

func Get(c *frame.Context, key string) (interface{}, error) {
	sess := mustPickSession(c)
	return sess.Get(key), nil
}

func Destroy(c *frame.Context) error {
	sess := mustPickSession(c)
	err := sess.Destroy()
	if err != nil {
		return err
	}
	return sess.Save()
}

func Save(c *frame.Context) error {
	sess := mustPickSession(c)
	return sess.Save()
}

func Fresh(c *frame.Context) (bool, error) {
	sess := mustPickSession(c)
	return sess.Fresh(), nil
}

func ID(c *frame.Context) (string, error) {
	sess := mustPickSession(c)
	return sess.ID(), nil
}

func Regenerate(c *frame.Context) error {
	sess := mustPickSession(c)
	return sess.Regenerate()
}

func mustPickSession(c *frame.Context) *Session {
	sess, err := DefaultSession.Get(c, DefaultSession.Config.ErrorHandler)
	if err != nil {
		panic(err)
	}
	return sess
}

func SetUser(c *frame.Context, user interface{}) error {
	return Set(c, "user", user)
}

func User(c *frame.Context) (interface{}, error) {
	return Get(c, "user")
}

func Register(i interface{}) {
	gob.Register(i)
}
