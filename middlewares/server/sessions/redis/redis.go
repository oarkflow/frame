package redis

import (
	"context"
	"errors"
	"github.com/redis/go-redis/v9"
	"github.com/sujit-baniya/frame/middlewares/server/sessions"
)

type Store interface {
	sessions.Store
}

type store struct {
	*RedisStore
}

func (s *store) Options(opts sessions.Options) {
	s.RedisStore.options = *opts.ToGorillaOptions()
}

func NewStore(addr, passwd string, db int) (Store, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: passwd,
		DB:       db,
	})
	s, err := NewRedisStore(context.Background(), client)
	if err != nil {
		return nil, err
	}
	return &store{s}, nil
}

// SetKeyPrefix sets the key prefix in the redis database.
func SetKeyPrefix(s Store, prefix string) error {
	redisStore, err := GetRedisStore(s)
	if err != nil {
		return err
	}
	redisStore.keyPrefix = prefix
	return nil
}

// GetRedisStore get the actual working store.
// Ref: https://godoc.org/github.com/boj/redistore#RedisStore
func GetRedisStore(s Store) (redisStore *RedisStore, err error) {
	realStore, ok := s.(*store)
	if !ok {
		err = errors.New("unable to get the redis store: Store isn't *store")
		return
	}

	redisStore = realStore.RedisStore
	return
}
