package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/luikyv/go-oidc/pkg/goidc"
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
	Issuer string `mapstructure:"issuer"`
}

// TODO Change this function in order to handle multiple key id.
func (c *Config) privateJWKSFunc() goidc.JWKSFunc {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	jwks := goidc.JSONWebKeySet{
		Keys: []goidc.JSONWebKey{{
			KeyID:     "key",
			Key:       privateKey,
			Algorithm: "RS256",
		}},
	}
	return func(_ context.Context) (goidc.JSONWebKeySet, error) {
		return jwks, err
	}
}
