package log

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sujit-baniya/frame"
	"github.com/sujit-baniya/frame/pkg/common/xid"
	"github.com/sujit-baniya/log"
)

type Config struct {
	Logger    *log.Logger
	LogWriter log.Writer
	RequestID func() string
}

// New Middleware request_id + logger + recover for request traceability
func New(config Config) frame.HandlerFunc {
	return func(c context.Context, ctx *frame.Context) {
		start := time.Now()
		if strings.Contains(string(ctx.Path()), "favicon") {
			ctx.Next(c)
			return
		}
		rid := string(ctx.GetHeader("X-Request-ID"))
		if config.RequestID == nil {
			config.RequestID = func() string {
				return xid.New().String()
			}
		}
		if rid == "" {
			rid = config.RequestID()
			ctx.Header("X-Request-ID", rid)
		}
		ctx.Next(c)

		if config.Logger == nil {
			config.Logger = &log.Logger{
				TimeField:  "timestamp",
				TimeFormat: "2006-01-02 15:04:05",
			}
		}
		if config.LogWriter != nil {
			config.Logger.Writer = config.LogWriter
		}
		ip := ctx.ClientIP()
		curIP := ctx.Value("ip")
		if curIP != nil {
			ip = curIP.(string)
		}
		logging := log.NewContext(nil).
			Str("request_id", rid).
			Str("remote_ip", ip).
			Str("method", string(ctx.Method())).
			Str("host", string(ctx.Host())).
			Str("path", string(ctx.Path())).
			Str("protocol", string(ctx.Request.Scheme())).
			Int("status", ctx.Response.StatusCode()).
			Str("latency", fmt.Sprintf("%s", time.Since(start))).
			Str("ua", string(ctx.GetHeader("User-Agent")))

		log.Info().Str("log_service", "HTTP Server").Str("request_id", rid).
			Str("remote_ip", ip).
			Str("method", string(ctx.Method())).
			Str("host", string(ctx.Host())).
			Str("path", string(ctx.Path())).
			Str("protocol", string(ctx.Request.Scheme())).
			Int("status", ctx.Response.StatusCode()).
			Str("latency", fmt.Sprintf("%s", time.Since(start))).
			Str("ua", string(ctx.GetHeader("User-Agent")))

		ctxx := logging.Value()
		switch {
		case ctx.Response.StatusCode() >= 500:
			config.Logger.Error().Context(ctxx).Msg("server error")
			log.Error().Str("log_service", "HTTP Server").Context(ctxx).Msg("server error")
		case ctx.Response.StatusCode() >= 400:
			config.Logger.Error().Context(ctxx).Msg("client error")
			log.Error().Str("log_service", "HTTP Server").Context(ctxx).Msg("client error")
		case ctx.Response.StatusCode() >= 300:
			config.Logger.Warn().Context(ctxx).Msg("redirect")
			log.Info().Str("log_service", "HTTP Server").Context(ctxx).Msg("redirect")
		case ctx.Response.StatusCode() >= 200:
			config.Logger.Info().Context(ctxx).Msg("success")
			log.Info().Str("log_service", "HTTP Server").Context(ctxx).Msg("success")
		case ctx.Response.StatusCode() >= 100:
			config.Logger.Info().Context(ctxx).Msg("informative")
			log.Info().Str("log_service", "HTTP Server").Context(ctxx).Msg("informative")
		default:
			config.Logger.Warn().Context(ctxx).Msg("unknown status")
			log.Info().Str("log_service", "HTTP Server").Context(ctxx).Msg("unknown status")
		}
	}
}
