package oidc

import (
	"context"
	"encoding/json"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"io"
	"log/slog"
	"os"
)

var allScopes = []goidc.Scope{
	goidc.ScopeOpenID,
	goidc.ScopeOfflineAccess,
	goidc.ScopeProfile,
	goidc.ScopeEmail,
	goidc.ScopeAddress,
	goidc.ScopePhone,
}

type Config struct {
	Issuer   string `mapstructure:"issuer"`
	JWKSPath string `mapstructure:"jwksPath"`
}

func (c *Config) PrivateJWKSFunc() goidc.JWKSFunc {
	return func(ctx context.Context) (goidc.JSONWebKeySet, error) {
		var jwks goidc.JSONWebKeySet

		jwksFile, err := os.Open(c.JWKSPath)
		if err != nil {
			slog.Error("Unable to open JWKS file", slog.Any("error", err))

			return jwks, err
		}
		defer func() {
			if err := jwksFile.Close(); err != nil {
				slog.Error("Unable to close JWKS file", slog.Any("error", err))
			}
		}()

		jwksBytes, err := io.ReadAll(jwksFile)
		if err != nil {
			slog.Error("Unable to read JWKS file", slog.Any("error", err))

			return jwks, err
		}

		if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
			slog.Error("Unable to unmarshal JWKS file", slog.Any("error", err))

			return jwks, err
		}
		return jwks, nil
	}
}
