package client

import (
	"errors"
	"fmt"
)

var ErrInvalidAuthenticationMethod = errors.New("invalid authentication method")

type AuthenticationMethod struct {
	slug string
}

// ParseAuthenticationMethod parses a given slug into an AuthenticationMethod instance or returns an error if invalid.
func ParseAuthenticationMethod(slug string) (AuthenticationMethod, error) {
	switch slug {
	case AuthenticationMethodClientSecretBasic.slug:
		return AuthenticationMethodClientSecretBasic, nil
	case AuthenticationMethodClientSecretPost.slug:
		return AuthenticationMethodClientSecretPost, nil
	case AuthenticationMethodClientSecretJwt.slug:
		return AuthenticationMethodClientSecretJwt, nil
	case AuthenticationMethodPrivateKeyJwt.slug:
		return AuthenticationMethodPrivateKeyJwt, nil
	case AuthenticationMethodNone.slug:
		return AuthenticationMethodNone, nil
	case AuthenticationMethodTlsClientAuth.slug:
		return AuthenticationMethodTlsClientAuth, nil
	case AuthenticationMethodSelfSignedTlsClientAuth.slug:
		return AuthenticationMethodSelfSignedTlsClientAuth, nil
	}
	return AuthenticationMethodUnknown, fmt.Errorf("%w: %q", ErrInvalidAuthenticationMethod, slug)
}

func (a AuthenticationMethod) MarshalText() ([]byte, error) {
	return []byte(a.slug), nil
}

func (a *AuthenticationMethod) UnmarshalText(text []byte) error {
	var err error
	*a, err = ParseAuthenticationMethod(string(text))
	return err
}

func (a AuthenticationMethod) String() string {
	return a.slug
}

var (
	AuthenticationMethodUnknown                 = AuthenticationMethod{slug: ""}
	AuthenticationMethodClientSecretBasic       = AuthenticationMethod{slug: "client_secret_basic"}
	AuthenticationMethodClientSecretPost        = AuthenticationMethod{slug: "client_secret_post"}
	AuthenticationMethodClientSecretJwt         = AuthenticationMethod{slug: "client_secret_jwt"}
	AuthenticationMethodPrivateKeyJwt           = AuthenticationMethod{slug: "private_key_jwt"}
	AuthenticationMethodNone                    = AuthenticationMethod{slug: "none"}
	AuthenticationMethodTlsClientAuth           = AuthenticationMethod{slug: "tls_client_auth"}
	AuthenticationMethodSelfSignedTlsClientAuth = AuthenticationMethod{slug: "self_signed_tls_client_auth"}
)
