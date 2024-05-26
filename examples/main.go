package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/paseto"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/middlewares/server/keyauth"
	logMiddleware "github.com/oarkflow/frame/middlewares/server/log"
	"github.com/oarkflow/frame/pkg/common/utils"
	"github.com/oarkflow/frame/server"
)

func main() {
	/*log.DefaultLogger = log.Logger{
		TimeField:     "timestamp",
		TimeFormat:    "2006-01-02 15:04:05",
		EnableTracing: true,
		Writer: &log.ConsoleWriter{
			ColorOutput:    true,
			QuoteString:    true,
			EndWithMessage: true,
		},
	}
	*/
	srv := server.New()
	srv.Use(logMiddleware.New(logMiddleware.Config{
		EnableTracing: true,
		UserIdentity: func(c *frame.Context) any {
			return 1
		},
	}))
	/*
		hndlr := func(c context.Context, ctx *frame.Context) {
			ctx.AbortWithJSON(200, utils.H{"error": "This is error"})
		}*/
	srv.GET("/", func(c context.Context, ctx *frame.Context) {
		ctx.JSON(200, "Hello world")
	})
	srv.GET("/update", func(c context.Context, ctx *frame.Context) {
		srv.GET("/", func(c context.Context, ctx *frame.Context) {
			ctx.JSON(200, "Bye World")
		})
	})
	srv.GET("/to-remove", func(c context.Context, ctx *frame.Context) {
		ctx.JSON(200, "Remove Route")
	})
	srv.GET("/remove", func(c context.Context, ctx *frame.Context) {
		route, err := srv.RemoveRoute("GET", "/to-remove")
		if err != nil {
			panic(err)
		}
		fmt.Println(route)
	})

	srv.Spin()
}

func pasetoEncDec() {
	secret := "OdR4DlWhZk6osDd0qXLdVT88lHOvj14K"
	v4 := paseto.NewPV4Local()
	key, err := paseto.NewSymmetricKey([]byte(secret), paseto.Version4)
	if err != nil {
		panic(err)
	}
	encrypted, err := v4.Encrypt(key, &paseto.RegisteredClaims{
		Issuer:     "oarkflow.com",
		Subject:    "test",
		Audience:   "auth.oarkflow.com",
		Expiration: paseto.TimePtr(time.Now().Add(time.Minute)),
		NotBefore:  paseto.TimePtr(time.Now()),
		IssuedAt:   paseto.TimePtr(time.Now()),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)
	decrypted := v4.Decrypt(encrypted, key)
	if decrypted.Err() != nil {
		panic(decrypted.Err())
	}
	var claim paseto.RegisteredClaims
	err = decrypted.ScanClaims(&claim)
	if err != nil {
		panic(err)
	}
	fmt.Println(claim, claim.TokenID)
}

func ma1in() {
	srv := server.Default(server.WithHostPorts(":8081"))
	auth := keyauth.New(
		keyauth.WithKeyLookUp("query:token", ""),
		keyauth.WithExpiration(true),
		keyauth.WithValidator(func(ctx context.Context, c *frame.Context, token string) (bool, error) {
			if opts, exists := c.Get("keyauth_options"); exists {
				options := opts.(*keyauth.Options)
				secret := "OdR4DlWhZk6osDd0qXLdVT88lHOvj14K"
				v4 := paseto.NewPV4Local()
				key, err := paseto.NewSymmetricKey([]byte(secret), paseto.Version4)
				if err != nil {
					return false, err
				}
				decrypted := v4.Decrypt(token, key)
				if err := decrypted.Err(); err != nil {
					return false, err
				}
				if options.HasExpiration() {
					var claim paseto.RegisteredClaims
					err = decrypted.ScanClaims(&claim)
					if err != nil {
						return false, err
					}
				}
			}
			return true, nil
		}),
	)
	srv.GET("/generate-key", func(c context.Context, ctx *frame.Context) {
		secret := "OdR4DlWhZk6osDd0qXLdVT88lHOvj14K"
		v4 := paseto.NewPV4Local()
		key, err := paseto.NewSymmetricKey([]byte(secret), paseto.Version4)
		if err != nil {
			panic(err)
		}
		now := time.Now()
		expiresAt := now.Add(time.Minute)
		encrypted, err := v4.Encrypt(key, &paseto.RegisteredClaims{
			Issuer:     "oarkflow.com",
			Subject:    "test",
			Audience:   "auth.oarkflow.com",
			Expiration: paseto.TimePtr(expiresAt),
			NotBefore:  paseto.TimePtr(now),
			IssuedAt:   paseto.TimePtr(now),
		})
		if err != nil {
			panic(err)
		}
		ctx.JSON(200, utils.H{
			"token": encrypted,
		})
		fmt.Println(encrypted)
	})
	srv.GET("/restricted", auth, func(c context.Context, ctx *frame.Context) {
		ctx.JSON(200, "Got access")
	})
	srv.Spin()
}
