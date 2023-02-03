package filesystem

import (
	"github.com/sujit-baniya/frame/middlewares/server/sessions"
	gsessions "github.com/sujit-baniya/sessions"
)

type Store interface {
	sessions.Store
}

type store struct {
	*gsessions.FilesystemStore
}

func (c *store) Options(opts sessions.Options) {
	c.FilesystemStore.Options = opts.ToGorillaOptions()
}

func NewStore(name, path string, keyPairs ...[]byte) Store {
	return &store{gsessions.NewFilesystemStore(name, path, keyPairs...)}
}
