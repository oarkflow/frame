package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type namedFile struct {
	Name     string       `json:"name"` // file/socket's name
	File     *os.File     `json:"-"`
	Addr     string       `json:"addr"` // socket's address
	Listener net.Listener `json:"-"`
}

// Parent process, hold files for inherit.
type Parent struct {
	Files []namedFile
}

// AddFile for inherit to child process.
func (p *Parent) AddFile(f *os.File) {
	p.add(namedFile{f.Name(), f, "", nil})
}

func listenerToFile(ln net.Listener) (*os.File, error) {
	switch t := ln.(type) {
	case *net.TCPListener:
		return t.File()
	case *net.UnixListener:
		return t.File()
	}
	return nil, fmt.Errorf("unsupported listener: %T", ln)
}

// AddListener for inherit to child process.
func (p *Parent) AddListener(l net.Listener, addr string) {
	p.add(namedFile{Listener: l, Addr: addr})
}

func (p *Parent) add(nfs ...namedFile) {
	if p.Files == nil {
		p.Files = make([]namedFile, 0, len(nfs))
	}
	p.Files = append(p.Files, nfs...)
}

func (p *Parent) forkChild() (*os.Process, error) {
	// Get current process name and directory.
	execFp, err := os.Executable()
	if err != nil {
		return nil, err
	}

	// Current folder maybe not same as folder of exec_fp
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	files := []*os.File{
		os.Stdin,
		os.Stdout,
		os.Stderr,
	}

	for _, nf := range p.Files {
		if nf.Addr == "" {
			files = append(files, nf.File)
		} else {
			lf, err := listenerToFile(p.Files[0].Listener)
			if err == nil {
				nf.File = lf
				nf.Name = lf.Name()
				files = append(files, nf.File)
			} else {
				fmt.Printf("listener to file failed: %s, ignored", err)
			}
		}
	}

	// Get current environment and add `endless` to it.
	bs, err := json.Marshal(p.Files)
	if err != nil {
		return nil, err
	}
	environment := append(os.Environ(), "ENDLESS="+string(bs))

	var args []string
	if len(os.Args) > 1 {
		args = os.Args[1:]
	}

	// Spawn child process.
	process, err := os.StartProcess(
		execFp,
		args,
		&os.ProcAttr{
			Dir:   dir,
			Env:   environment,
			Files: files,
			Sys:   &syscall.SysProcAttr{},
		},
	)
	if err != nil {
		return nil, err
	}

	return process, nil
}

// WaitForSignal wait for signal
func (p *Parent) WaitForSignal(quit func(ctx context.Context) error) error {
	signalCh := make(chan os.Signal, 1024)
	signal.Notify(signalCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT)
	for {
		s := <-signalCh
		fmt.Printf("receive signal.%v\n", s)

		switch s {
		case syscall.SIGHUP:
			proc, err := p.forkChild()
			if err != nil {
				fmt.Printf("unable fork child: %s\n", err)
				continue
			}

			fmt.Printf("forked child: %d\n", proc.Pid)
			proc.Release() // must wait

		case syscall.SIGINT, syscall.SIGQUIT:
			// Create a context that will expire in 5 seconds and use this as a
			// timeout to Shutdown.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

			err := quit(ctx)

			defer cancel()
			p.Quit()
			return err
		}
	}
}

func (p *Parent) Quit() {
	for _, nf := range p.Files {
		if nf.Addr != "" && nf.File != nil {
			nf.File.Close()
		}
	}
}

// Start Main entry for endless.
// In `init_parent` normally create listener.
// In `init_child` normally inherit the listener.
func Start(
	initParent func(p *Parent) error,
	initChild func(c *Child) error,
	quit func(ctx context.Context) error,
) {
	env := os.Getenv("ENDLESS")
	if env == "" {
		// it's parent, wait for SIGHUP
		p := new(Parent)
		if initParent(p) != nil {
			os.Exit(1)
			return
		}

		err := p.WaitForSignal(quit)
		if err != nil {
			fmt.Printf("parent wait failed: %s\n", err)
		}
		return
	}

	c := newClient(env)
	if c == nil {
		os.Exit(2)
		return
	}

	err := initChild(c)
	if err != nil {
		fmt.Printf("init child failed: %s\n", err)
		os.Exit(3)
		return
	}

	c.Ready()

	err = c.WaitForSignal(quit)
	if err != nil {
		fmt.Printf("quit failed: %s\n", err)
	}
}

type Child struct {
	*Parent
	NamedFiles map[string]namedFile
}

func newClient(env string) *Child {
	var nfs []namedFile
	err := json.Unmarshal([]byte(env), &nfs)
	if err != nil {
		fmt.Printf("parse endless('%s') failed: %s\n", env, err)
		return nil
	}

	c := Child{&Parent{}, map[string]namedFile{}}

	firstFd := 3

	for i, nf := range nfs {
		if nf.Addr != "" {
			file := os.NewFile(uintptr(firstFd+i), nf.Name)
			defer file.Close()
			nf.Listener, err = net.FileListener(file)
			if err != nil {
				fmt.Printf("create listener inner failed: %s\n", err)
			}
			c.NamedFiles[nf.Addr] = nf
		} else {
			nf.File = os.NewFile(uintptr(firstFd+i), nf.Name)
			c.NamedFiles[nf.Name] = nf
		}
	}
	return &c
}

func (c *Child) Ready() {
	proc, err := os.FindProcess(os.Getppid())
	if err != nil {
		fmt.Printf("find parent failed %s\n", err)
		return
	}

	err = proc.Signal(os.Interrupt)
	if err != nil {
		fmt.Printf("signal int to parent failed %s\n", err)
		return
	}

	fmt.Print("signal to parent done\n")
}
