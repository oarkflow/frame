package websocket

import (
	"github.com/sujit-baniya/frame"
)

type handleMessageFunc func(*Session, []byte)
type handleErrorFunc func(*Session, error)
type handleCloseFunc func(*Session, int, string) error
type handleSessionFunc func(*Session)
type filterFunc func(*Session) bool

// Hub implements a websocket manager.
type Hub struct {
	Config                   *Config
	Upgrader                 *Upgrader
	messageHandler           handleMessageFunc
	messageHandlerBinary     handleMessageFunc
	messageSentHandler       handleMessageFunc
	messageSentHandlerBinary handleMessageFunc
	errorHandler             handleErrorFunc
	closeHandler             handleCloseFunc
	connectHandler           handleSessionFunc
	disconnectHandler        handleSessionFunc
	pongHandler              handleSessionFunc
	hub                      *hub
}

// NewHub creates a new hub instance with default Upgrader and Config.
func NewHub() *Hub {
	upgrader := &Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024 * 100,
		CheckOrigin:     func(r *frame.Context) bool { return true },
	}

	hub := newHub()

	go hub.run()

	return &Hub{
		Config:                   newConfig(),
		Upgrader:                 upgrader,
		messageHandler:           func(*Session, []byte) {},
		messageHandlerBinary:     func(*Session, []byte) {},
		messageSentHandler:       func(*Session, []byte) {},
		messageSentHandlerBinary: func(*Session, []byte) {},
		errorHandler:             func(*Session, error) {},
		closeHandler:             nil,
		connectHandler:           func(*Session) {},
		disconnectHandler:        func(*Session) {},
		pongHandler:              func(*Session) {},
		hub:                      hub,
	}
}

// OnConnect fires fn when a session connects.
func (m *Hub) OnConnect(fn func(*Session)) {
	m.connectHandler = fn
}

// OnDisconnect fires fn when a session disconnects.
func (m *Hub) OnDisconnect(fn func(*Session)) {
	m.disconnectHandler = fn
}

// OnPong fires fn when a pong is received from a session.
func (m *Hub) OnPong(fn func(*Session)) {
	m.pongHandler = fn
}

// OnMessage fires fn when a text message comes in.
func (m *Hub) OnMessage(fn func(*Session, []byte)) {
	m.messageHandler = fn
}

// OnBinaryMessage fires fn when a binary message comes in.
func (m *Hub) OnBinaryMessage(fn func(*Session, []byte)) {
	m.messageHandlerBinary = fn
}

// OnMessageSent fires fn when a text message is successfully sent.
func (m *Hub) OnMessageSent(fn func(*Session, []byte)) {
	m.messageSentHandler = fn
}

// OnBinaryMessageSent fires fn when a binary message is successfully sent.
func (m *Hub) OnBinaryMessageSent(fn func(*Session, []byte)) {
	m.messageSentHandlerBinary = fn
}

// OnError fires fn when a session has an error.
func (m *Hub) OnError(fn func(*Session, error)) {
	m.errorHandler = fn
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
	if fn != nil {
		m.closeHandler = fn
	}
}

// OnRequest upgrades http requests to websocket connections and dispatches them to be handled by the hub instance.
func (m *Hub) OnRequest(ctx *frame.Context) error {
	return m.OnRequestWithKeys(ctx, nil)
}

// OnRequestWithKeys does the same as HandleRequest but populates session.Keys with keys.
func (m *Hub) OnRequestWithKeys(ctx *frame.Context, keys map[string]interface{}) error {
	if m.hub.closed() {
		return ErrClosed
	}
	m.Upgrader.Subprotocols = []string{string(ctx.GetHeader("Sec-WebSocket-Protocol"))}
	return m.Upgrader.Upgrade(ctx, func(conn *Conn) {
		session := NewSession(ctx, conn, keys, m.Config.MessageBufferSize)
		session.hub = m
		m.hub.register <- session
		m.connectHandler(session)
		go session.writePump()
		session.readPump()
		if !m.hub.closed() {
			m.hub.unregister <- session
		}
		session.close()
		m.disconnectHandler(session)
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
			if writeErr := session.Write(msg); writeErr != nil {
				return writeErr
			}
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
