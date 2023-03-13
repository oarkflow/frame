package log

import (
	"context"
	"fmt"
	"time"

	"github.com/sujit-baniya/frame"
	"github.com/sujit-baniya/frame/pkg/common/xid"
	"github.com/sujit-baniya/log"
)

type Config struct {
	Logger    *log.Logger
	LogWriter log.Writer
	RequestID func() string
	Skip      func(c *frame.Context) bool
}

func New(config Config) frame.HandlerFunc {
	return func(ctx context.Context, c *frame.Context) {
		start := time.Now()
		c.Next(ctx)
		end := time.Now()
		latency := end.Sub(start)

		if config.Skip != nil && config.Skip(c) {
			return
		}
		rid := string(c.GetHeader("X-Request-ID"))
		if config.RequestID == nil {
			config.RequestID = func() string {
				return xid.New().String()
			}
		}
		if rid == "" {
			rid = config.RequestID()
			c.Header("X-Request-ID", rid)
		}

		if config.Logger == nil {
			config.Logger = &log.Logger{
				TimeField:  "timestamp",
				TimeFormat: "2006-01-02 15:04:05",
			}
		}
		ip := c.ClientIP()
		curIP := ctx.Value("ip")
		if curIP != nil {
			ip = curIP.(string)
		}

		status := c.Response.StatusCode()
		msg := "Request"
		var e *log.Entry
		switch {
		case status >= 500:
			e = config.Logger.Error()
			msg = "Server Error"
		case status >= 400 && status < 500:
			e = config.Logger.Warn()
			msg = "Client Error"
		case status >= 300 && status < 400:
			e = config.Logger.Warn()
			msg = "Redirect"
		case status >= 200 && status < 300:
			e = config.Logger.Info()
			msg = "Success"
		case status >= 100:
			e = config.Logger.Info()
			msg = "Informative"
		default:
			e = config.Logger.Info()
			msg = "Unknown"
		}
		if !log.DefaultLogger.EnableTracing {
			e = e.Str("request_id", rid)
		}
		e.WithContext(ctx).Str("log_service", "HTTP Server").
			Int("status", status).
			Str("remote_ip", ip).
			Str("method", string(c.Method())).
			Str("host", string(c.Host())).
			Str("path", string(c.Path())).
			Str("protocol", string(c.Request.Scheme())).
			Int("status", c.Response.StatusCode()).
			Str("latency", fmt.Sprintf("%s", latency)).
			Str("ua", string(c.GetHeader("User-Agent"))).
			Msg(msg)
	}
}
