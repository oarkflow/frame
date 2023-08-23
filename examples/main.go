package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/common/utils"
	"github.com/oarkflow/frame/pkg/websocket"
	"github.com/oarkflow/frame/server"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

var addr = ":8080"

func serveHome(_ context.Context, c *frame.Context) {
	c.HTML(http.StatusOK, "index", nil)
}
func serveChan(_ context.Context, c *frame.Context) {
	channel := c.Param("id")
	c.HTML(http.StatusOK, "chan", utils.H{
		"channel": channel,
	})
}

func main() {
	hub := websocket.NewHub()

	h := server.Default(server.WithHostPorts(addr))
	h.SetHTMLTemplate("./", ".html")
	h.GET("/", serveHome)
	h.GET("/channel/:id", serveChan)
	h.GET("/ws/:channel", func(c context.Context, ctx *frame.Context) {
		channel := ctx.Param("channel")
		sessionID, err := hub.OnRequest(ctx)
		if err != nil {
			ctx.JSON(500, err.Error())
		} else {
			go func() {
				time.Sleep(1 * time.Second)
				session := hub.SessionByID(sessionID)
				if session != nil {
					session.Channels = append(session.Channels, channel)
				}
				hub.Notify([]byte(fmt.Sprintf("Welcome to <strong>%s</strong> channel", channel)), sessionID)
			}()
		}
	})
	hub.OnConnect(func(s *websocket.Session) {
		fmt.Println("Connected")
	})
	hub.OnError(func(session *websocket.Session, err error) {
	})
	hub.OnMessage(func(currentSession *websocket.Session, msg []byte) {
		hub.BroadcastFilter(msg, func(activeSession *websocket.Session) bool {
			channel := activeSession.Request.Param("channel")
			return slices.Contains(currentSession.Channels, channel)
		})
	})
	h.Spin()
}
