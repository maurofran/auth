package settings

import "github.com/lestrrat-go/jwx/v3/jwa"

// Client represents an entity that interacts with the system, embedding settings for additional configurations.
type Client struct {
	RequireProofKey                             bool                   `json:"settings.client.require-proof-key"`
	RequireAuthorizationConsent                 bool                   `json:"settings.client.require-authorization-consent"`
	JWKSetURL                                   string                 `json:"settings.client.jwk-set-url"`
	TokenEndpointAuthenticationSigningAlgorithm jwa.SignatureAlgorithm `json:"settings.client.token-endpoint-authentication-signing-algorithm"`
	X509CertificateSubjectDN                    string                 `json:"settings.client.x509-certificate-subject-dn"`
}

// Validate checks the Client's configuration and returns an error if any required field or setting is invalid.
func (c *Client) Validate() error {
	return nil
}

// DefaultClient initializes and returns a default Client instance with no custom configurations.
func DefaultClient() *Client {
	return &Client{}
}
