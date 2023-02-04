package filesystem

import (
	"github.com/sujit-baniya/frame/middlewares/server/session"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Filesystem struct {
	path      string
	prefix    string
	fileMutex sync.RWMutex
}

func New(cfg ...Config) session.Storage {
	var config Config
	if len(cfg) > 0 {
		config = cfg[0]
	}
	if config.Path == "" {
		config.Path = "./"
	}
	if config.Prefix != "" {
		config.Prefix = config.Prefix + "_"
	}
	return &Filesystem{path: config.Path, prefix: config.Prefix, fileMutex: sync.RWMutex{}}
}

func (f *Filesystem) Get(key string) ([]byte, error) {
	filename := filepath.Join(f.path, f.prefix+key)
	f.fileMutex.Lock()
	defer f.fileMutex.Unlock()
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func (f *Filesystem) Set(key string, val []byte, exp time.Duration) error {
	filename := filepath.Join(f.path, f.prefix+key)
	f.fileMutex.Lock()
	defer f.fileMutex.Unlock()
	return os.WriteFile(filename, val, 0600)
}

func (f *Filesystem) Delete(key string) error {
	filename := filepath.Join(f.path, f.prefix+key)
	f.fileMutex.RLock()
	defer f.fileMutex.RUnlock()
	err := os.Remove(filename)
	return err
}

func (f *Filesystem) Reset() error {
	return os.RemoveAll(f.path)
}

func (f *Filesystem) Close() error {
	return nil
}
