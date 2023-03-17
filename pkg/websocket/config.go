package websocket

import (
	"github.com/oarkflow/frame"
	"time"
)

// Config hub configuration struct.
type Config struct {
	WriteWait         time.Duration // Milliseconds until write times out.
	PongWait          time.Duration // Timeout for waiting on pong.
	PingPeriod        time.Duration // Milliseconds between pings.
	MaxMessageSize    int64         // Maximum size in bytes of a message.
	MessageBufferSize int           // The max amount of messages that can be in a sessions buffer before it starts dropping them.
	AutoCleanSession  bool
	CleanInterval     time.Duration
	Upgrader          *Upgrader
	Handlers          *Handlers
}

func defaultConfig(config *Config) {
	if config.WriteWait == 0 {
		config.WriteWait = 10 * time.Second
	}
	if config.PongWait == 0 {
		config.PongWait = time.Minute
	}
	if config.PingPeriod == 0 {
		config.PingPeriod = (time.Minute * 9) / 10
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 512
	}
	if config.MessageBufferSize == 0 {
		config.MessageBufferSize = 256
	}
	if config.CleanInterval == 0 {
		config.CleanInterval = time.Minute
	}
	if config.Upgrader == nil {
		config.Upgrader = &Upgrader{}
	}
	if config.Handlers == nil {
		config.Handlers = &Handlers{}
	}
	defaultUpgrader(config.Upgrader)
	defaultHandlers(config.Handlers)
}

func defaultUpgrader(upgrader *Upgrader) {
	if upgrader.ReadBufferSize == 0 {
		upgrader.ReadBufferSize = 1024
	}
	if upgrader.WriteBufferSize == 0 {
		upgrader.WriteBufferSize = 102400
	}
	if upgrader.CheckOrigin == nil {
		upgrader.CheckOrigin = func(r *frame.Context) bool { return true }
	}
}

func defaultHandlers(handlers *Handlers) {
	if handlers.ConnectHandler == nil {
		handlers.ConnectHandler = func(session *Session) {}
	}
	if handlers.DisconnectHandler == nil {
		handlers.DisconnectHandler = func(session *Session) {}
	}
	if handlers.PongHandler == nil {
		handlers.PongHandler = func(session *Session) {}
	}
	if handlers.BinaryMessageHandler == nil {
		handlers.BinaryMessageHandler = func(session *Session, bytes []byte) {}
	}
	if handlers.MessageHandler == nil {
		handlers.MessageHandler = func(session *Session, bytes []byte) {}
	}
	if handlers.MessageSentHandler == nil {
		handlers.MessageSentHandler = func(session *Session, bytes []byte) {}
	}
	if handlers.BinaryMessageSentHandler == nil {
		handlers.BinaryMessageSentHandler = func(session *Session, bytes []byte) {}
	}
	if handlers.CloseHandler == nil {
		handlers.CloseHandler = func(session *Session, i int, s string) error {
			return nil
		}
	}
}
