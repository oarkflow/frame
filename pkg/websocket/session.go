package websocket

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oarkflow/frame"
)

// Session wrapper around websocket connections.
type Session struct {
	ID         string
	Request    *frame.Context
	Channels   []string
	Keys       map[string]interface{}
	conn       *Conn
	output     chan *envelope
	outputDone chan struct{}
	hub        *Hub
	open       bool
	rwmutex    *sync.RWMutex
}

func NewSession(id string, ctx *frame.Context, conn *Conn, keys map[string]any, messageBufferSize int) *Session {
	return &Session{
		ID:         id,
		Request:    ctx,
		Keys:       keys,
		Channels:   []string{},
		conn:       conn,
		output:     make(chan *envelope, messageBufferSize),
		outputDone: make(chan struct{}),
		open:       true,
		rwmutex:    &sync.RWMutex{},
	}
}

func (s *Session) writeMessage(message *envelope) error {
	if s.closed() {
		s.hub.config.Handlers.ErrorHandler(s, ErrWriteClosed)
		return ErrWriteClosed
	}

	select {
	case s.output <- message:
	default:
		s.hub.config.Handlers.ErrorHandler(s, ErrMessageBufferFull)
		return ErrMessageBufferFull
	}
	return nil
}

func (s *Session) writeRaw(message *envelope) error {
	if s.closed() {
		return ErrWriteClosed
	}

	s.conn.SetWriteDeadline(time.Now().Add(s.hub.config.WriteWait))
	err := s.conn.WriteMessage(message.t, message.msg)

	if err != nil {
		return err
	}

	return nil
}

func (s *Session) closed() bool {
	s.rwmutex.RLock()
	defer s.rwmutex.RUnlock()

	return !s.open
}

func (s *Session) close() {
	s.rwmutex.Lock()
	open := s.open
	s.open = false
	s.rwmutex.Unlock()
	if open {
		s.conn.Close()
		close(s.outputDone)
	}
}

func (s *Session) ping() {
	s.writeRaw(&envelope{t: PingMessage, msg: []byte{}})
}

func (s *Session) writePump() {
	ticker := time.NewTicker(s.hub.config.PingPeriod)
	defer ticker.Stop()

loop:
	for {
		select {
		case msg := <-s.output:
			err := s.writeRaw(msg)
			if s.hub.config.Handlers.ErrorHandler == nil {
				s.hub.config.Handlers.ErrorHandler = func(session *Session, err error) {
					fmt.Println("Caught error on", session.ID, err.Error())
				}
			}
			if err != nil {
				s.hub.config.Handlers.ErrorHandler(s, err)
				break loop
			}

			if msg.t == CloseMessage {
				break loop
			}

			if msg.t == TextMessage {
				s.hub.config.Handlers.MessageSentHandler(s, msg.msg)
			}

			if msg.t == BinaryMessage {
				s.hub.config.Handlers.BinaryMessageSentHandler(s, msg.msg)
			}
		case <-ticker.C:
			s.ping()
		case _, ok := <-s.outputDone:
			if !ok {
				break loop
			}
		}
	}
}

func (s *Session) readPump() {
	s.conn.SetReadLimit(s.hub.config.MaxMessageSize)
	s.conn.SetReadDeadline(time.Now().Add(s.hub.config.PongWait))

	s.conn.SetPongHandler(func(string) error {
		s.conn.SetReadDeadline(time.Now().Add(s.hub.config.PongWait))
		s.hub.config.Handlers.PongHandler(s)
		return nil
	})

	if s.hub.config.Handlers.CloseHandler != nil {
		s.conn.SetCloseHandler(func(code int, text string) error {
			return s.hub.config.Handlers.CloseHandler(s, code, text)
		})
	}

	for {
		t, message, err := s.conn.ReadMessage()

		if err != nil {
			s.hub.config.Handlers.ErrorHandler(s, err)
			break
		}

		if t == TextMessage {
			s.hub.config.Handlers.MessageHandler(s, message)
		}

		if t == BinaryMessage {
			s.hub.config.Handlers.BinaryMessageSentHandler(s, message)
		}
	}
}

// Write writes message to session.
func (s *Session) Write(msg []byte) error {
	if s.closed() {
		return ErrSessionClosed
	}

	return s.writeMessage(&envelope{t: TextMessage, msg: msg})
}

// WriteBinary writes a binary message to session.
func (s *Session) WriteBinary(msg []byte) error {
	if s.closed() {
		return ErrSessionClosed
	}

	return s.writeMessage(&envelope{t: BinaryMessage, msg: msg})
}

// Close closes session.
func (s *Session) Close() error {
	if s.closed() {
		return ErrSessionClosed
	}

	return s.writeMessage(&envelope{t: CloseMessage, msg: []byte{}})
}

// CloseWithMsg closes the session with the provided payload.
// Use the FormatCloseMessage function to format a proper close message payload.
func (s *Session) CloseWithMsg(msg []byte) error {
	if s.closed() {
		return ErrSessionClosed
	}

	return s.writeMessage(&envelope{t: CloseMessage, msg: msg})
}

// Set is used to store a new key/value pair exclusively for this session.
// It also lazy initializes s.Keys if it was not used previously.
func (s *Session) Set(key string, value interface{}) {
	s.rwmutex.Lock()
	defer s.rwmutex.Unlock()

	if s.Keys == nil {
		s.Keys = make(map[string]interface{})
	}

	s.Keys[key] = value
}

// Get returns the value for the given key, ie: (value, true).
// If the value does not exists it returns (nil, false)
func (s *Session) Get(key string) (value interface{}, exists bool) {
	s.rwmutex.RLock()
	defer s.rwmutex.RUnlock()

	if s.Keys != nil {
		value, exists = s.Keys[key]
	}

	return
}

// MustGet returns the value for the given key if it exists, otherwise it panics.
func (s *Session) MustGet(key string) interface{} {
	if value, exists := s.Get(key); exists {
		return value
	}

	panic("Key \"" + key + "\" does not exist")
}

// IsClosed returns the status of the connection.
func (s *Session) IsClosed() bool {
	return s.closed()
}

// LocalAddr returns the local addr of the connection.
func (s *Session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the remote addr of the connection.
func (s *Session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}
