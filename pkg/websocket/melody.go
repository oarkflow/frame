package websocket

import (
	"github.com/sujit-baniya/frame"
	"github.com/sujit-baniya/frame/pkg/common/xid"
)

type HandleMessageFunc func(*Session, []byte)
type HandleErrorFunc func(*Session, error)
type HandleCloseFunc func(*Session, int, string) error
type HandleSessionFunc func(*Session)
type FilterFunc func(*Session) bool

type Handlers struct {
	MessageHandler           HandleMessageFunc
	BinaryMessageHandler     HandleMessageFunc
	MessageSentHandler       HandleMessageFunc
	BinaryMessageSentHandler HandleMessageFunc
	ErrorHandler             HandleErrorFunc
	CloseHandler             HandleCloseFunc
	ConnectHandler           HandleSessionFunc
	DisconnectHandler        HandleSessionFunc
	PongHandler              HandleSessionFunc
}

// Hub implements a websocket manager.
type Hub struct {
	config *Config
	hub    *hub
}

// NewHub creates a new hub instance with default Upgrader and Config.
func NewHub(cfg ...*Config) *Hub {
	var config *Config
	if len(cfg) > 0 {
		config = cfg[0]
	} else {
		config = &Config{}
	}
	defaultConfig(config)
	hub := newHub()
	go hub.run()
	return &Hub{
		config: config,
		hub:    hub,
	}
}

// OnConnect fires fn when a session connects.
func (m *Hub) OnConnect(fn func(*Session)) {
	m.config.Handlers.ConnectHandler = fn
}

// OnDisconnect fires fn when a session disconnects.
func (m *Hub) OnDisconnect(fn func(*Session)) {
	m.config.Handlers.DisconnectHandler = fn
}

// OnPong fires fn when a pong is received from a session.
func (m *Hub) OnPong(fn func(*Session)) {
	m.config.Handlers.PongHandler = fn
}

// OnMessage fires fn when a text message comes in.
func (m *Hub) OnMessage(fn func(*Session, []byte)) {
	m.config.Handlers.MessageHandler = fn
}

// OnBinaryMessage fires fn when a binary message comes in.
func (m *Hub) OnBinaryMessage(fn func(*Session, []byte)) {
	m.config.Handlers.BinaryMessageHandler = fn
}

// OnMessageSent fires fn when a text message is successfully sent.
func (m *Hub) OnMessageSent(fn func(*Session, []byte)) {
	m.config.Handlers.MessageSentHandler = fn
}

// OnBinaryMessageSent fires fn when a binary message is successfully sent.
func (m *Hub) OnBinaryMessageSent(fn func(*Session, []byte)) {
	m.config.Handlers.BinaryMessageSentHandler = fn
}

// OnError fires fn when a session has an error.
func (m *Hub) OnError(fn func(*Session, error)) {
	m.config.Handlers.ErrorHandler = fn
}

// OnClose sets the handler for close messages received from the session.
// The code argument to h is the received close code or CloseNoStatusReceived
// if the close message is empty. The default close handler sends a close frame
// back to the session.
//
// The application must read the connection to process close messages as
// described in the section on Control Frames above.
//
// The connection read methods return a CloseError when a close frame is
// received. Most applications should handle close messages as part of their
// normal error handling. Applications should only set a close handler when the
// application must perform some action before sending a close frame back to
// the session.
func (m *Hub) OnClose(fn func(*Session, int, string) error) {
	m.config.Handlers.CloseHandler = fn
}

// OnRequest upgrades http requests to websocket connections and dispatches them to be handled by the hub instance.
func (m *Hub) OnRequest(ctx *frame.Context) (string, error) {
	return m.OnRequestWithKeys(ctx, nil)
}

// OnRequestWithKeys does the same as HandleRequest but populates session.Keys with keys.
func (m *Hub) OnRequestWithKeys(ctx *frame.Context, keys map[string]interface{}) (string, error) {
	if m.hub.closed() {
		return "", ErrClosed
	}
	m.config.Upgrader.Subprotocols = []string{string(ctx.GetHeader("Sec-WebSocket-Protocol"))}
	id := xid.New().String()
	return id, m.config.Upgrader.Upgrade(ctx, func(conn *Conn) {
		session := NewSession(id, ctx, conn, keys, m.config.MessageBufferSize)
		session.hub = m
		m.hub.register <- session
		m.config.Handlers.ConnectHandler(session)
		go session.writePump()
		session.readPump()
		if !m.hub.closed() {
			m.hub.unregister <- session
		}
		session.close()
		m.config.Handlers.DisconnectHandler(session)
	})
}

// Broadcast broadcasts a text message to all sessions.
func (m *Hub) Broadcast(msg []byte) error {
	if m.hub.closed() {
		return ErrClosed
	}

	message := &envelope{t: TextMessage, msg: msg}
	m.hub.broadcast <- message

	return nil
}

// Notify broadcasts a text message to all sessions.
func (m *Hub) Notify(msg []byte, sessionID string) error {
	if m.hub.closed() {
		return ErrClosed
	}
	for _, session := range m.hub.all() {
		if session.ID == sessionID {
			return session.Write(msg)
		}
	}
	return nil
}

// BroadcastFilter broadcasts a text message to all sessions that fn returns true for.
func (m *Hub) BroadcastFilter(msg []byte, fn func(*Session) bool) error {
	if m.hub.closed() {
		return ErrClosed
	}

	message := &envelope{t: TextMessage, msg: msg, filter: fn}
	m.hub.broadcast <- message

	return nil
}

// BroadcastExcept broadcasts a text message to all sessions except session s.
func (m *Hub) BroadcastExcept(msg []byte, s *Session) error {
	return m.BroadcastFilter(msg, func(q *Session) bool {
		return s != q
	})
}

// BroadcastMultiple broadcasts a text message to multiple sessions given in the sessions slice.
func (m *Hub) BroadcastMultiple(msg []byte, sessions []*Session) error {
	for _, sess := range sessions {
		if writeErr := sess.Write(msg); writeErr != nil {
			return writeErr
		}
	}
	return nil
}

// BroadcastBinary broadcasts a binary message to all sessions.
func (m *Hub) BroadcastBinary(msg []byte) error {
	if m.hub.closed() {
		return ErrClosed
	}

	message := &envelope{t: BinaryMessage, msg: msg}
	m.hub.broadcast <- message

	return nil
}

// BroadcastBinaryFilter broadcasts a binary message to all sessions that fn returns true for.
func (m *Hub) BroadcastBinaryFilter(msg []byte, fn func(*Session) bool) error {
	if m.hub.closed() {
		return ErrClosed
	}

	message := &envelope{t: BinaryMessage, msg: msg, filter: fn}
	m.hub.broadcast <- message

	return nil
}

// BroadcastBinaryOthers broadcasts a binary message to all sessions except session s.
func (m *Hub) BroadcastBinaryOthers(msg []byte, s *Session) error {
	return m.BroadcastBinaryFilter(msg, func(q *Session) bool {
		return s != q
	})
}

// Sessions returns all sessions. An error is returned if the hub session is closed.
func (m *Hub) Sessions() ([]*Session, error) {
	if m.hub.closed() {
		return nil, ErrClosed
	}
	return m.hub.all(), nil
}

// SessionByID returns all sessions. An error is returned if the hub session is closed.
func (m *Hub) SessionByID(sessionID string) *Session {
	for _, session := range m.hub.all() {
		if session.ID == sessionID {
			return session
		}
	}
	return nil
}

// Close closes the hub instance and all connected sessions.
func (m *Hub) Close() error {
	if m.hub.closed() {
		return ErrClosed
	}

	m.hub.exit <- &envelope{t: CloseMessage, msg: []byte{}}

	return nil
}

// CloseWithMsg closes the hub instance with the given close payload and all connected sessions.
// Use the FormatCloseMessage function to format a proper close message payload.
func (m *Hub) CloseWithMsg(msg []byte) error {
	if m.hub.closed() {
		return ErrClosed
	}

	m.hub.exit <- &envelope{t: CloseMessage, msg: msg}

	return nil
}

// Len return the number of connected sessions.
func (m *Hub) Len() int {
	return m.hub.len()
}

// IsClosed returns the status of the hub instance.
func (m *Hub) IsClosed() bool {
	return m.hub.closed()
}
