package oidc

import (
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

var claims = []string{
	goidc.ClaimEmail, goidc.ClaimEmailVerified, goidc.ClaimPhoneNumber,
	goidc.ClaimPhoneNumberVerified, goidc.ClaimAddress,
}

var acrs = []goidc.ACR{goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver}

var displayValues = []goidc.DisplayValue{goidc.DisplayValuePage, goidc.DisplayValuePopUp}

// NewProvider creates a new provider starting with supplied configuration
func NewProvider(
	config Config,
	clientStorage goidc.ClientManager,
	grantSessionStorage goidc.GrantSessionManager,
	authnSessionManager goidc.AuthnSessionManager,
	policy goidc.AuthnPolicy,
) (*provider.Provider, error) {
	return provider.New(
		goidc.ProfileOpenID,
		config.Issuer,
		config.PrivateJWKSFunc(),
		provider.WithScopes(allScopes...),
		provider.WithIDTokenSignatureAlgs(goidc.RS256, goidc.None),
		provider.WithUserInfoSignatureAlgs(goidc.RS256, goidc.None),
		// See https://auth0.com/blog/what-are-oauth-push-authorization-requests-par/ for PAR requests
		provider.WithPAR(10),
		provider.WithJAR(goidc.RS256, goidc.None),
		provider.WithJARByReference(false),
		provider.WithJARM(goidc.RS256),
		provider.WithTokenAuthnMethods(
			goidc.ClientAuthnSecretBasic,
			goidc.ClientAuthnSecretPost,
			goidc.ClientAuthnPrivateKeyJWT,
		),
		provider.WithPrivateKeyJWTSignatureAlgs(goidc.RS256),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithImplicitGrant(),
		provider.WithAuthorizationCodeGrant(),
		provider.WithClientCredentialsGrant(),
		provider.WithRefreshTokenGrant(nil, 600), // authutil.IssueRefreshToken
		provider.WithClaims(claims[0], claims...),
		provider.WithACRs(acrs[0], acrs...),
		// provider.WithDCR(authutil.DCRFunc, authutil.ValidateInitialTokenFunc),
		// provider.WithTokenOptions(authutil.TokenOptionsFunc(goidc.RS256)),
		// provider.WithHTTPClientFunc(authutil.HTTPClient),
		provider.WithPolicy(policy),
		// provider.WithNotifyErrorFunc(authutil.ErrorLoggingFunc),
		// provider.WithRenderErrorFunc(authutil.RenderError(templatesDirPath)),
		provider.WithDisplayValues(displayValues[0], displayValues...),
		provider.WithSubIdentifierTypes(goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise),
		provider.WithClientStorage(clientStorage),
		provider.WithGrantSessionStorage(grantSessionStorage),
		provider.WithAuthnSessionStorage(authnSessionManager),
	)
}
