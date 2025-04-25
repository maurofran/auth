package oidc

import (
	"context"
	"crypto/tls"
	"embed"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
	"github.com/maurofran/kernel/logger"
	"html/template"
	"log/slog"
	"net/http"
	"slices"
)

//go:embed templates/*.gohtml
var templates embed.FS

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
		config.privateJWKSFunc(),
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
		provider.WithRefreshTokenGrant(ShouldIssueRefreshToken, 600),
		provider.WithClaims(claims[0], claims...),
		provider.WithACRs(acrs[0], acrs...),
		provider.WithDCR(dcrHandler, dcrValidator),
		provider.WithTokenOptions(TokenOptions(goidc.RS256)),
		provider.WithHTTPClientFunc(HttpClient),
		provider.WithPolicy(policy),
		provider.WithNotifyErrorFunc(LogError),
		provider.WithRenderErrorFunc(RenderError()),
		provider.WithDisplayValues(displayValues[0], displayValues...),
		provider.WithSubIdentifierTypes(goidc.SubIdentifierPublic, goidc.SubIdentifierPairwise),
		provider.WithClientStorage(clientStorage),
		provider.WithGrantSessionStorage(grantSessionStorage),
		provider.WithAuthnSessionStorage(authnSessionManager),
	)
}

func ShouldIssueRefreshToken(client *goidc.Client, _ goidc.GrantInfo) bool {
	return slices.Contains(client.GrantTypes, goidc.GrantRefreshToken)
}

func TokenOptions(alg goidc.SignatureAlgorithm) goidc.TokenOptionsFunc {
	return func(grantInfo goidc.GrantInfo, _ *goidc.Client) goidc.TokenOptions {
		opts := goidc.NewJWTTokenOptions(alg, 600)
		return opts
	}
}

func LogError(ctx context.Context, err error) {
	slog.ErrorContext(ctx, "An error occurred while handling the request", slog.Any(logger.ErrorKey, err))
}

type errorPage struct {
	Error string
}

func RenderError() goidc.RenderErrorFunc {
	tpls, err := template.ParseFS(templates, "templates/error.gohtml")
	if err != nil {
		slog.Error("Unable to parse error template", slog.Any(logger.ErrorKey, err))
	}

	return func(w http.ResponseWriter, r *http.Request, err error) error {
		w.WriteHeader(http.StatusOK)
		err = tpls.Execute(w, errorPage{
			Error: err.Error(),
		})
		if err != nil {
			slog.Error("Unable to render error template", slog.Any(logger.ErrorKey, err))
		}
		return nil
	}
}

func HttpClient(ctx context.Context) *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}
