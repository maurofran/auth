package settings

import "fmt"

// Server represents a server configuration wrapper that embeds settings for flexible configuration management.
type Server struct {
	Issuer                             string `json:"settings.authorization-server.issuer" mapstructure:"issuer"`
	MultipleIssuersAllowed             bool   `json:"settings.authorization-server.multiple-issuers-allowed" mapstructure:"multiple-issuers-allowed"`
	AuthorizationEndpoint              string `json:"settings.authorization-server.authorization-endpoint" mapstructure:"authorization-endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"settings.authorization-server.pushed-authorization-request-endpoint" mapstructure:"pushed-authorization-request-endpoint"`
	DeviceAuthorizationEndpoint        string `json:"settings.authorization-server.device-authorization-endpoint" mapstructure:"device-authorization-endpoint"`
	DeviceVerificationEndpoint         string `json:"settings.authorization-server.device-verification-endpoint" mapstructure:"device-verification-endpoint"`
	TokenEndpoint                      string `json:"settings.authorization-server.token-endpoint" mapstructure:"token-endpoint"`
	JWKSetEndpoint                     string `json:"settings.authorization-server.jwk-set-endpoint" mapstructure:"jwk-set-endpoint"`
	TokenRevocationEndpoint            string `json:"settings.authorization-server.token-revocation-endpoint" mapstructure:"token-revocation-endpoint"`
	TokenIntrospectionEndpoint         string `json:"settings.authorization-server.token-introspection-endpoint" mapstructure:"token-introspection-endpoint"`
	OIDCClientRegistrationEndpoint     string `json:"settings.authorization-server.oidc-client-registration-endpoint" mapstructure:"oidc-client-registration-endpoint"`
	OIDCUserInfoEndpoint               string `json:"settings.authorization-server.oidc-user-info-endpoint" mapstructure:"oidc-user-info-endpoint"`
	OIDCLogoutEndpoint                 string `json:"settings.authorization-server.oidc-logout-endpoint" mapstructure:"oidc-logout-endpoint"`
}

// Validate checks the Server's configuration for invalid settings and returns an error if any are found.
func (s *Server) Validate() error {
	if s.Issuer != "" && s.MultipleIssuersAllowed {
		return fmt.Errorf("%w: the issuer identifier cannot be set when multiple issuers are allowed", ErrInvalidSetting)
	}
	return nil
}

// DefaultServer initializes and returns a Server with default endpoints for various OAuth2 and OIDC functionalities.
func DefaultServer() *Server {
	return &Server{
		MultipleIssuersAllowed:             false,
		AuthorizationEndpoint:              "/oauth2/authorize",
		PushedAuthorizationRequestEndpoint: "/oauth2/par",
		DeviceAuthorizationEndpoint:        "/oauth2/device_authorization",
		DeviceVerificationEndpoint:         "/oauth2/device_verification",
		TokenEndpoint:                      "/oauth2/token",
		JWKSetEndpoint:                     "/oauth2/jwks",
		TokenRevocationEndpoint:            "/oauth2/revoke",
		TokenIntrospectionEndpoint:         "/oauth2/introspect",
		OIDCClientRegistrationEndpoint:     "/connect/register",
		OIDCUserInfoEndpoint:               "/userinfo",
		OIDCLogoutEndpoint:                 "/connect/logout",
	}
}
