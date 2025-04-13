package client

import (
	"errors"
	"fmt"
	"github.com/maurofran/auth/internal/domain/client/authorization"
	"github.com/maurofran/auth/internal/domain/settings"
	"net/url"
	"slices"
	"time"
)

// A Registered client is a representation of a client that is registered with the authorization server. A client must
// be registered with the authorization server before it can initiate an authorization grant flow, such as
// authorization_code or client_credentials.
type Registered struct {
	ID                      uint
	ClientID                string
	ClientIDIssuedAt        time.Time
	ClientSecret            string
	ClientSecretExpiresAt   time.Time
	Name                    string
	AuthenticationMethods   []AuthenticationMethod
	AuthorizationGrantTypes []authorization.GrantType
	RedirectUris            []string
	PostLogoutRedirectUris  []string
	Scopes                  []string
	ClientSettings          *settings.Client
	TokenSettings           *settings.Token
}

func (r *Registered) isPublicClient() bool {
	return slices.Contains(r.AuthorizationGrantTypes, authorization.GrantTypeAuthorizationCode) &&
		len(r.AuthenticationMethods) == 1 &&
		slices.Contains(r.AuthenticationMethods, AuthenticationMethodNone)
}

func (r *Registered) validateScopes() error {
	for _, scope := range r.Scopes {
		for _, r := range []rune(scope) {
			if r != 0x21 && (r < 0x23 || r > 0x58) && (r < 0x5d || r > 0x7e) {
				return fmt.Errorf("scope %q contains invalid characters", scope)
			}
		}
	}
	return nil
}

func (r *Registered) validateRedirectUris() error {
	for _, redirectUri := range r.RedirectUris {
		if uri, err := url.ParseRequestURI(redirectUri); err != nil || uri.Fragment != "" {
			return fmt.Errorf("redirect_uri %q is not a valid redirect URI or contains fragment", redirectUri)
		}
	}
	return nil
}

func (r *Registered) validatePostLogoutRedirectUris() error {
	for _, postLogoutRedirectUri := range r.PostLogoutRedirectUris {
		if uri, err := url.ParseRequestURI(postLogoutRedirectUri); err != nil || uri.Fragment != "" {
			return fmt.Errorf("post_logout_redirect_uri %q is not a valid redirect URI or contains fragment", postLogoutRedirectUri)
		}
	}
	return nil
}

// Validate ensures the Registered instance has valid configurations and populates defaults for missing settings.
func (r *Registered) Validate() error {
	var err error
	if r.ClientID == "" {
		err = errors.Join(err, errors.New("clientID cannot be empty"))
	}
	if len(r.AuthorizationGrantTypes) == 0 {
		err = errors.Join(err, errors.New("authorizationGrantTypes cannot be empty"))
	}
	if slices.Contains(r.AuthorizationGrantTypes, authorization.GrantTypeAuthorizationCode) && len(r.RedirectUris) == 0 {
		err = errors.Join(err, errors.New("redirectUris cannot be empty"))
	}
	if r.Name == "" {
		err = errors.Join(err, errors.New("name cannot be empty"))
	}
	if len(r.AuthenticationMethods) == 0 {
		r.AuthenticationMethods = []AuthenticationMethod{AuthenticationMethodClientSecretBasic}
	}
	if r.ClientSettings == nil {
		r.ClientSettings = &settings.Client{}
		if r.isPublicClient() {
			r.ClientSettings.RequireProofKey = true
			r.ClientSettings.RequireAuthorizationConsent = true
		}
	}
	if r.TokenSettings == nil {
		r.TokenSettings = &settings.Token{}
	}
	return errors.Join(err, r.validateScopes(), r.validateRedirectUris(), r.validatePostLogoutRedirectUris())
}
