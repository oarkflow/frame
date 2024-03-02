// The MIT License (MIT)
//
// Copyright (c) 2016 Bo-Yi Wu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// This file may have been modified by Frame authors. All Frame
// Modifications are Copyright 2022 Frame Authors.

package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oarkflow/frame"
	"github.com/oarkflow/frame/pkg/protocol"

	"github.com/golang-jwt/jwt/v5"
)

// MapClaims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// FrameJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type FrameJWTMiddleware struct {
	TimeFunc                    func() time.Time
	IdentityHandler             func(ctx context.Context, c *frame.Context) interface{}
	privKey                     *rsa.PrivateKey
	KeyFunc                     func(token *jwt.Token) (interface{}, error)
	HTTPStatusMessageFunc       func(e error, ctx context.Context, c *frame.Context) string
	pubKey                      *rsa.PublicKey
	Authenticator               func(ctx context.Context, c *frame.Context) (interface{}, error)
	Authorizator                func(data interface{}, ctx context.Context, c *frame.Context) bool
	PayloadFunc                 func(data interface{}) MapClaims
	Unauthorized                func(ctx context.Context, c *frame.Context, code int, message string)
	LoginResponse               func(ctx context.Context, c *frame.Context, code int, message string, time time.Time)
	LogoutResponse              func(ctx context.Context, c *frame.Context, code int)
	RefreshResponse             func(ctx context.Context, c *frame.Context, code int, message string, time time.Time)
	SigningAlgorithm            string
	IdentityKey                 string
	TokenLookup                 string
	TokenHeadName               string
	CookieDomain                string
	Realm                       string
	CookieName                  string
	PrivKeyFile                 string
	PubKeyFile                  string
	PrivateKeyPassphrase        string
	PrivKeyBytes                []byte
	PubKeyBytes                 []byte
	Key                         []byte
	CookieSameSite              protocol.CookieSameSite
	CookieMaxAge                time.Duration
	MaxRefresh                  time.Duration
	Timeout                     time.Duration
	SendCookie                  bool
	SecureCookie                bool
	CookieHTTPOnly              bool
	WithoutDefaultTokenHeadName bool
	SendAuthorization           bool
	DisabledAbort               bool
	PartialCookie               bool
}

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = errors.New("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = errors.New("FrameJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = errors.New("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = errors.New("incorrect Username or Password")

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = errors.New("failed to create JWT Token")

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired") // in practice, this is generated from the jwt library not by us

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = errors.New("missing exp field")

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = errors.New("exp must be float64 format")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = errors.New("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = errors.New("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")

	// IdentityKey default identity key
	IdentityKey = "identity"
)

// New for check error with FrameJWTMiddleware
func New(m *FrameJWTMiddleware) (*FrameJWTMiddleware, error) {
	if err := m.MiddlewareInit(); err != nil {
		return nil, err
	}

	return m, nil
}

func (mw *FrameJWTMiddleware) readKeys() error {
	err := mw.privateKey()
	if err != nil {
		return err
	}
	err = mw.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (mw *FrameJWTMiddleware) privateKey() error {
	var keyData []byte
	if mw.PrivKeyFile == "" {
		keyData = mw.PrivKeyBytes
	} else {
		filecontent, err := os.ReadFile(mw.PrivKeyFile)
		if err != nil {
			return ErrNoPrivKeyFile
		}
		keyData = filecontent
	}

	if mw.PrivateKeyPassphrase != "" {
		key, err := jwt.ParseRSAPrivateKeyFromPEMWithPassword(keyData, mw.PrivateKeyPassphrase) //lint:ignore SA1019 ignoreCheck
		if err != nil {
			return ErrInvalidPrivKey
		}
		mw.privKey = key
		return nil
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.privKey = key
	return nil
}

func (mw *FrameJWTMiddleware) publicKey() error {
	var keyData []byte
	if mw.PubKeyFile == "" {
		keyData = mw.PubKeyBytes
	} else {
		filecontent, err := os.ReadFile(mw.PubKeyFile)
		if err != nil {
			return ErrNoPubKeyFile
		}
		keyData = filecontent
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey = key
	return nil
}

func (mw *FrameJWTMiddleware) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

// MiddlewareInit initialize jwt configs.
func (mw *FrameJWTMiddleware) MiddlewareInit() error {
	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if len(mw.TokenHeadName) == 0 && !mw.WithoutDefaultTokenHeadName {
		mw.TokenHeadName = "Bearer"
	}

	if mw.Authorizator == nil {
		mw.Authorizator = func(data interface{}, ctx context.Context, c *frame.Context) bool {
			return true
		}
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(ctx context.Context, c *frame.Context, code int, message string) {
			c.JSON(code, map[string]interface{}{
				"code":    code,
				"message": message,
			})
		}
	}

	if mw.LoginResponse == nil {
		mw.LoginResponse = func(ctx context.Context, c *frame.Context, code int, token string, expire time.Time) {
			c.JSON(http.StatusOK, map[string]interface{}{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if mw.LogoutResponse == nil {
		mw.LogoutResponse = func(ctx context.Context, c *frame.Context, code int) {
			c.JSON(http.StatusOK, map[string]interface{}{
				"code": http.StatusOK,
			})
		}
	}

	if mw.RefreshResponse == nil {
		mw.RefreshResponse = func(ctx context.Context, c *frame.Context, code int, token string, expire time.Time) {
			c.JSON(http.StatusOK, map[string]interface{}{
				"code":   http.StatusOK,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if mw.IdentityKey == "" {
		mw.IdentityKey = IdentityKey
	}

	if mw.IdentityHandler == nil {
		mw.IdentityHandler = func(ctx context.Context, c *frame.Context) interface{} {
			claims := ExtractClaims(ctx, c)
			return claims[mw.IdentityKey]
		}
	}

	if mw.HTTPStatusMessageFunc == nil {
		mw.HTTPStatusMessageFunc = func(e error, ctx context.Context, c *frame.Context) string {
			return e.Error()
		}
	}

	if mw.Realm == "" {
		mw.Realm = "frame jwt"
	}

	if mw.CookieMaxAge == 0 {
		mw.CookieMaxAge = mw.Timeout
	}

	if mw.CookieName == "" {
		mw.CookieName = "jwt"
	}

	// bypass other key settings if KeyFunc is set
	if mw.KeyFunc != nil {
		return nil
	}

	if mw.usingPublicKeyAlgo() {
		return mw.readKeys()
	}

	if mw.Key == nil {
		return ErrMissingSecretKey
	}
	return nil
}

// MiddlewareFunc makes FrameJWTMiddleware implement the Middleware interface.
func (mw *FrameJWTMiddleware) MiddlewareFunc() frame.HandlerFunc {
	return func(ctx context.Context, c *frame.Context) {
		mw.middlewareImpl(ctx, c)
	}
}

func (mw *FrameJWTMiddleware) middlewareImpl(ctx context.Context, c *frame.Context) {
	claims, err := mw.GetClaimsFromJWT(ctx, c)
	if err != nil {
		mw.unauthorized(ctx, c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, ctx, c))
		return
	}

	if claims["exp"] == nil {
		mw.unauthorized(ctx, c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrMissingExpField, ctx, c))
		return
	}

	if _, ok := claims["exp"].(float64); !ok {
		mw.unauthorized(ctx, c, http.StatusBadRequest, mw.HTTPStatusMessageFunc(ErrWrongFormatOfExp, ctx, c))
		return
	}

	if int64(claims["exp"].(float64)) < mw.TimeFunc().Unix() {
		mw.unauthorized(ctx, c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, ctx, c))
		return
	}

	c.Set("JWT_PAYLOAD", claims)
	identity := mw.IdentityHandler(ctx, c)

	if identity != nil {
		c.Set(mw.IdentityKey, identity)
	}

	if !mw.Authorizator(identity, ctx, c) {
		mw.unauthorized(ctx, c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, ctx, c))
		return
	}

	c.Next(ctx)
}

// GetClaimsFromJWT get claims from JWT token
func (mw *FrameJWTMiddleware) GetClaimsFromJWT(ctx context.Context, c *frame.Context) (MapClaims, error) {
	token, err := mw.ParseToken(ctx, c)
	if err != nil {
		return nil, err
	}

	if mw.SendAuthorization {
		if v, ok := c.Get("JWT_TOKEN"); ok {
			c.Header("Authorization", mw.TokenHeadName+" "+v.(string))
		}
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *FrameJWTMiddleware) LoginHandler(ctx context.Context, c *frame.Context) {
	if mw.Authenticator == nil {
		mw.unauthorized(ctx, c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, ctx, c))
		return
	}

	data, err := mw.Authenticator(ctx, c)
	if err != nil {
		mw.unauthorized(ctx, c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, ctx, c))
		return
	}

	// Create the token
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().Add(mw.Timeout)
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)
	if err != nil {
		mw.unauthorized(ctx, c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrFailedTokenCreation, ctx, c))
		return
	}

	// set cookie
	if mw.SendCookie {
		expireCookie := mw.TimeFunc().Add(mw.CookieMaxAge)
		maxage := int(expireCookie.Unix() - mw.TimeFunc().Unix())
		c.SetCookie(mw.CookieName, tokenString, maxage, "/", mw.CookieDomain, mw.CookieSameSite, mw.SecureCookie, mw.CookieHTTPOnly, mw.PartialCookie)
	}

	mw.LoginResponse(ctx, c, http.StatusOK, tokenString, expire)
}

// LogoutHandler can be used by clients to remove the jwt cookie (if set)
func (mw *FrameJWTMiddleware) LogoutHandler(ctx context.Context, c *frame.Context) {
	// delete auth cookie
	if mw.SendCookie {
		c.SetCookie(mw.CookieName, "", -1, "/", mw.CookieDomain, mw.CookieSameSite, mw.SecureCookie, mw.CookieHTTPOnly, mw.PartialCookie)
	}

	mw.LogoutResponse(ctx, c, http.StatusOK)
}

func (mw *FrameJWTMiddleware) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if mw.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(mw.privKey)
	} else {
		tokenString, err = token.SignedString(mw.Key)
	}
	return tokenString, err
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the FrameJWTMiddleware.
// Reply will be of the form {"token": "TOKEN"}.
func (mw *FrameJWTMiddleware) RefreshHandler(ctx context.Context, c *frame.Context) {
	tokenString, expire, err := mw.RefreshToken(ctx, c)
	if err != nil {
		mw.unauthorized(ctx, c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, ctx, c))
		return
	}

	mw.RefreshResponse(ctx, c, http.StatusOK, tokenString, expire)
}

// RefreshToken refresh token and check if token is expired
func (mw *FrameJWTMiddleware) RefreshToken(ctx context.Context, c *frame.Context) (string, time.Time, error) {
	claims, err := mw.CheckIfTokenExpire(ctx, c)
	if err != nil {
		return "", time.Now(), err
	}

	// Create the token
	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)

	for key := range claims {
		newClaims[key] = claims[key]
	}

	expire := mw.TimeFunc().Add(mw.Timeout)
	newClaims["exp"] = expire.Unix()
	newClaims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(newToken)
	if err != nil {
		return "", time.Now(), err
	}

	// set cookie
	if mw.SendCookie {
		expireCookie := mw.TimeFunc().Add(mw.CookieMaxAge)
		maxage := int(expireCookie.Unix() - time.Now().Unix())
		c.SetCookie(mw.CookieName, tokenString, maxage, "/", mw.CookieDomain, mw.CookieSameSite, mw.SecureCookie, mw.CookieHTTPOnly, mw.PartialCookie)
	}

	return tokenString, expire, nil
}

// CheckIfTokenExpire check if token expire
func (mw *FrameJWTMiddleware) CheckIfTokenExpire(ctx context.Context, c *frame.Context) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(ctx, c)
	if err != nil {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

// TokenGenerator method that clients can use to get a jwt token.
func (mw *FrameJWTMiddleware) TokenGenerator(data interface{}) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if mw.PayloadFunc != nil {
		for key, value := range mw.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := mw.TimeFunc().UTC().Add(mw.Timeout)
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = mw.TimeFunc().Unix()
	tokenString, err := mw.signedString(token)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expire, nil
}

func (mw *FrameJWTMiddleware) jwtFromHeader(ctx context.Context, c *frame.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !((len(parts) == 1 && mw.WithoutDefaultTokenHeadName && mw.TokenHeadName == "") ||
		(len(parts) == 2 && parts[0] == mw.TokenHeadName)) {
		return "", ErrInvalidAuthHeader
	}

	return parts[len(parts)-1], nil
}

func (mw *FrameJWTMiddleware) jwtFromQuery(ctx context.Context, c *frame.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (mw *FrameJWTMiddleware) jwtFromCookie(ctx context.Context, c *frame.Context, key string) (string, error) {
	cookie := string(c.Cookie(key))

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (mw *FrameJWTMiddleware) jwtFromParam(ctx context.Context, c *frame.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

// ParseToken parse jwt token from frame context
func (mw *FrameJWTMiddleware) ParseToken(ctx context.Context, c *frame.Context) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(mw.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = mw.jwtFromHeader(ctx, c, v)
		case "query":
			token, err = mw.jwtFromQuery(ctx, c, v)
		case "cookie":
			token, err = mw.jwtFromCookie(ctx, c, v)
		case "param":
			token, err = mw.jwtFromParam(ctx, c, v)
		}
	}

	if err != nil {
		return nil, err
	}

	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc)
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		// save token string if valid
		c.Set("JWT_TOKEN", token)

		return mw.Key, nil
	})
}

// ParseTokenString parse jwt token string
func (mw *FrameJWTMiddleware) ParseTokenString(token string) (*jwt.Token, error) {
	if mw.KeyFunc != nil {
		return jwt.Parse(token, mw.KeyFunc)
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}

		return mw.Key, nil
	})
}

func (mw *FrameJWTMiddleware) unauthorized(ctx context.Context, c *frame.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+mw.Realm)
	if !mw.DisabledAbort {
		c.Abort()
	}

	mw.Unauthorized(ctx, c, code, message)
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(ctx context.Context, c *frame.Context) MapClaims {
	claims, exists := c.Get("JWT_PAYLOAD")
	if !exists {
		return make(MapClaims)
	}

	return claims.(MapClaims)
}

// ExtractClaimsFromToken help to extract the JWT claims from token
func ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

// GetToken help to get the JWT token string
func GetToken(ctx context.Context, c *frame.Context) string {
	token, exists := c.Get("JWT_TOKEN")
	if !exists {
		return ""
	}

	return token.(string)
}
