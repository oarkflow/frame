package main

/*func main() {
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

func main() {
	srv := server.Default(server.WithHostPorts(":8081"))
	srv.Use(keyauth.New(
		keyauth.WithKeyLookUp("query:token", ""),
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
				if decrypted.Err() != nil {
					return false, decrypted.Err()
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
	))
	srv.GET("/restricted", func(c context.Context, ctx *frame.Context) {
		ctx.JSON(200, "Got access")
	})
	srv.Spin()
}
*/
