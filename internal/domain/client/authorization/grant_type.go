package authorization

import "fmt"

// ErrInvalidGrantType is returned when an unrecognized or unsupported grant type is encountered.
var ErrInvalidGrantType = fmt.Errorf("invalid grant type")

// GrantType represents a structure containing a slug field as a string identifier or key.
type GrantType struct {
	slug string
}

// ParseGrantType parses a string into a corresponding GrantType or returns an error if the input is invalid.
func ParseGrantType(s string) (GrantType, error) {
	switch s {
	case GrantTypeAuthorizationCode.slug:
		return GrantTypeAuthorizationCode, nil
	case GrantTypeRefreshToken.slug:
		return GrantTypeRefreshToken, nil
	case GrantTypeClientCredentials.slug:
		return GrantTypeClientCredentials, nil
	case GrantTypePassword.slug:
		return GrantTypePassword, nil
	case GrantTypeJwtBearer.slug:
		return GrantTypeJwtBearer, nil
	case GrantTypeDeviceCode.slug:
		return GrantTypeDeviceCode, nil
	case GrantTypeTokenExchange.slug:
		return GrantTypeTokenExchange, nil
	}
	return GrantTypeUnknown, fmt.Errorf("%w: %q", ErrInvalidGrantType, s)
}

func (g GrantType) MarshalText() ([]byte, error) {
	return []byte(g.slug), nil
}

func (g *GrantType) UnmarshalText(text []byte) error {
	var err error
	*g, err = ParseGrantType(string(text))
	return err
}

func (g GrantType) String() string {
	return g.slug
}

var (
	GrantTypeUnknown           = GrantType{slug: ""}
	GrantTypeAuthorizationCode = GrantType{slug: "authorization_code"}
	GrantTypeRefreshToken      = GrantType{slug: "refresh_token"}
	GrantTypeClientCredentials = GrantType{slug: "client_credentials"}
	GrantTypePassword          = GrantType{slug: "password"} // Deprecated grant type
	GrantTypeJwtBearer         = GrantType{slug: "urn:ietf:params:oauth:grant-type:jwt-bearer"}
	GrantTypeDeviceCode        = GrantType{slug: "urn:ietf:params:oauth:grant-type:device_code"}
	GrantTypeTokenExchange     = GrantType{slug: "urn:ietf:params:oauth:grant-type:token-exchange"}
)
