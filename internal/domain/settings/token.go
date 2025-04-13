package settings

import (
	"fmt"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/maurofran/auth/internal/domain/token"
	"time"
)

const (
	authorizationCodeTimeToLive = "settings.token.authorization-code-time-to-live"
	accessCodeTimeToLive        = "settings.token.access-code-time-to-live"
	accessTokenFormat           = "settings.token.access-token-format"
	deviceCodeTimeToLive        = "settings.token.device-code-time-to-live"
	reuseRefreshToken           = "settings.token.reuse-refresh-token"
	refreshTokenTimeToLive      = "settings.token.refresh-token-time-to-live"
	idTokenSignatureAlgorithm   = "settings.token.id-token-signature-algorithm"
	x509BoundAccessTokens       = "settings.token.x509-bound-access-tokens"
)

const (
	defaultAuthorizationCodeTimeToLive = 5 * time.Minute
	defaultAccessCodeTimeToLive        = 5 * time.Minute
	defaultDeviceCodeTimeToLive        = 5 * time.Minute
	defaultRefreshTokenTimeToLive      = 60 * time.Minute
)

// Token represents a structure that embeds settings for managing configuration or key-value entries.
type Token struct {
	AuthorizationCodeTimeToLive time.Duration          `json:"settings.token.authorization-code-time-to-live"`
	AccessCodeTimeToLive        time.Duration          `json:"settings.token.access-code-time-to-live"`
	AccessTokenFormat           token.Format           `json:"settings.token.access-token-format"`
	DeviceCodeTimeToLive        time.Duration          `json:"settings.token.device-code-time-to-live"`
	ReuseRefreshToken           bool                   `json:"settings.token.reuse-refresh-token"`
	RefreshTokenTimeToLive      time.Duration          `json:"settings.token.refresh-token-time-to-live"`
	IDTokenSignatureAlgorithm   jwa.SignatureAlgorithm `json:"settings.token.id-token-signature-algorithm"`
	X509BoundAccessTokens       bool                   `json:"settings.token.x509-bound-access-tokens"`
}

// Validate checks the Token's settings for validity and returns an error if any configuration is invalid.
func (t *Token) Validate() error {
	switch {
	case t.AuthorizationCodeTimeToLive <= 0:
		return fmt.Errorf("%w: authorization code time-to-live should be greater than 0", ErrInvalidSetting)
	case t.AccessCodeTimeToLive <= 0:
		return fmt.Errorf("%w: access code time-to-live should be greater than 0", ErrInvalidSetting)
	case t.AccessTokenFormat == token.FormatUnknown:
		return fmt.Errorf("%w: unknown token format", ErrInvalidSetting)
	case t.DeviceCodeTimeToLive <= 0:
		return fmt.Errorf("%w: device code time-to-live should be greater than 0", ErrInvalidSetting)
	case t.RefreshTokenTimeToLive <= 0:
		return fmt.Errorf("%w: refresh token time-to-live should be greater than 0", ErrInvalidSetting)
	case t.IDTokenSignatureAlgorithm == jwa.EmptySignatureAlgorithm():
		return fmt.Errorf("%w: empty signature algorithm", ErrInvalidSetting)
	}
	return nil
}

// DefaultToken initializes and returns a pointer to a Token with default token configuration settings.
func DefaultToken() *Token {
	return &Token{
		AuthorizationCodeTimeToLive: defaultAuthorizationCodeTimeToLive,
		AccessCodeTimeToLive:        defaultAccessCodeTimeToLive,
		AccessTokenFormat:           token.FormatSelfContained,
		DeviceCodeTimeToLive:        defaultDeviceCodeTimeToLive,
		ReuseRefreshToken:           true,
		RefreshTokenTimeToLive:      defaultRefreshTokenTimeToLive,
		IDTokenSignatureAlgorithm:   jwa.RS256(),
		X509BoundAccessTokens:       false,
	}
}
