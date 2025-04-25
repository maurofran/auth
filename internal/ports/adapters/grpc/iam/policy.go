package iam

import (
	"embed"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/maurofran/auth/internal/domain/session"
	"github.com/maurofran/iam/pkg/protobuf"
	"github.com/maurofran/kernel/logger"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
)

const (
	policyID = "iam"

	stepParam              = "step"
	logoURIParam           = "logoURI"
	policyURIParam         = "policyURI"
	termsOfServiceURIParam = "termsOfServiceURI"
	tenantNameParam        = "tenantName"
	authTimeParam          = "authTime"
	userSessionIDParam     = "userSessionId"

	loadUserStep      = "loadUser"
	loginStep         = "login"
	createSessionStep = "createSession"
	consentStep       = "consent"
	finishFlowStep    = "finishFlow"

	usernameFormParam = "username"
	passwordFormParam = "password"
	loginFormParam    = "login"
	consentFormParam  = "consent"

	userSessionIDCookie = "auth_username"
)

//go:embed templates/*.gohtml
var templates embed.FS

// Policy retrieves an authentication policy defined in the system.
// It returns a goidc.AuthnPolicy object that encapsulates the policy settings.
func Policy(issuer string, sessionStore session.Store, client protobuf.IdentityServiceClient) (goidc.AuthnPolicy, error) {
	tpls, err := template.ParseFS(templates, "templates/*.gohtml")
	if err != nil {
		slog.Error("Error parsing templates", slog.Any(logger.ErrorKey, err))

		return goidc.AuthnPolicy{}, err
	}

	a := &Authenticator{
		template:     tpls,
		issuer:       issuer,
		sessionStore: sessionStore,
		client:       client,
	}

	return goidc.NewPolicy(
		policyID,
		startAuthentication,
		a.authenticate,
	), nil
}

func startAuthentication(request *http.Request, client *goidc.Client, session *goidc.AuthnSession) bool {
	ctx := request.Context()

	slog.InfoContext(ctx, "Starting authentication")

	session.StoreParameter(stepParam, loadUserStep)
	if client.LogoURI != "" {
		slog.DebugContext(ctx, "Adding logoURI to authentication session",
			slog.String("logoURI", client.LogoURI))

		session.StoreParameter(logoURIParam, client.LogoURI)
	}
	if client.PolicyURI != "" {
		slog.DebugContext(ctx, "Adding policyURI to authentication session",
			slog.String("policyURI", client.PolicyURI))

		session.StoreParameter(policyURIParam, client.PolicyURI)
	}
	if client.TermsOfServiceURI != "" {
		slog.DebugContext(ctx, "Adding termsOfServiceURI to authentication session",
			slog.String("termsOfServiceURI", client.TermsOfServiceURI))

		session.StoreParameter(termsOfServiceURIParam, client.TermsOfServiceURI)
	}
	// TODO Check if the client.Name can be the tenant name.
	if value := client.Attribute(tenantNameParam); value != nil {
		if tenantName, ok := value.(string); ok {
			slog.DebugContext(ctx, "Adding tenantName to authentication session",
				slog.String("tenantName", client.Name))

			session.StoreParameter(tenantNameParam, tenantName)
		}
	}
	return true
}

type Authenticator struct {
	client       protobuf.IdentityServiceClient
	sessionStore session.Store
	template     *template.Template
	issuer       string
}

func (a *Authenticator) authenticate(w http.ResponseWriter, req *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	if session.StoredParameter(stepParam) == loadUserStep {
		if status, err := a.loadUser(req, session); status != goidc.StatusSuccess {
			return status, err
		}
		session.StoreParameter(stepParam, loginStep)
	}
	if session.StoredParameter(stepParam) == loginStep {
		if status, err := a.login(w, req, session); status != goidc.StatusSuccess {
			return status, err
		}
		session.StoreParameter(stepParam, createSessionStep)
	}
	if session.StoredParameter(stepParam) == createSessionStep {
		if status, err := a.createUserSession(w, req, session); status != goidc.StatusSuccess {
			return status, err
		}
		session.StoreParameter(stepParam, consentStep)
	}
	if session.StoredParameter(stepParam) == consentStep {
		if status, err := a.grantConsent(w, req, session); status != goidc.StatusSuccess {
			return status, err
		}
		session.StoreParameter(stepParam, finishFlowStep)
	}
	if session.StoredParameter(stepParam) == finishFlowStep {
		return a.finishFlow(req, session)
	}
	return goidc.StatusFailure, errors.New("access denied")
}

func (a *Authenticator) loadUser(req *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	ctx := req.Context()

	cookie, err := req.Cookie(userSessionIDCookie)
	if err != nil {
		slog.WarnContext(ctx, "No user session cookie found", slog.Any(logger.ErrorKey, err))

		return goidc.StatusSuccess, nil
	}

	userSession, err := a.sessionStore.Get(ctx, cookie.Value)
	if err != nil {
		slog.ErrorContext(ctx, "Error retrieving user session", slog.Any(logger.ErrorKey, err))

		return goidc.StatusFailure, err
	} else if userSession == nil {
		slog.DebugContext(ctx, "User session not found")

		return goidc.StatusSuccess, nil
	}

	session.SetUserID(userSession.Subject)
	session.StoreParameter(authTimeParam, userSession.AuthTime)
	session.StoreParameter(userSessionIDParam, userSession.ID)

	return goidc.StatusSuccess, nil
}

func (a *Authenticator) login(w http.ResponseWriter, req *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	// If the user is unknown and the client requested no prompt for credentials, return a login-required error.
	if session.Subject == "" && session.Prompt == goidc.PromptTypeNone {
		err := goidc.NewError(goidc.ErrorCodeLoginRequired, "user not logged in, cannot use prompt none")
		return goidc.StatusFailure, err
	}
	// Determine if authentication is required: authentication is required if the user's identity is unknown or if the
	// client explicitly requested a login.
	mustAuthenticate := session.Subject == "" || session.Prompt == goidc.PromptTypeLogin
	// Additionally, check if the client specified a max age for the session.
	// If the max age is exceeded or 'auth_time' is unavailable, force re-authentication.
	if session.MaxAuthnAgeSecs != nil {
		maxAgeSecs := *session.MaxAuthnAgeSecs
		authTime := session.StoredParameter(authTimeParam)
		if authTime == nil || unixNow() > authTime.(int)+maxAgeSecs {
			mustAuthenticate = true
		}
	}
	if !mustAuthenticate {
		return goidc.StatusSuccess, nil
	}
	if err := req.ParseForm(); err != nil {
		return goidc.StatusFailure, err
	}
	isLogin := req.PostFormValue(loginFormParam)
	if isLogin == "" {
		return a.renderPage(w, "login", session)
	}
	if isLogin != "true" {
		return goidc.StatusFailure, errors.New("consent not granted")
	}
	request := &protobuf.AuthenticateUserRequest{
		TenantName: session.StoredParameter(tenantNameParam).(string),
		Username:   req.PostFormValue(usernameFormParam),
		Password:   req.PostFormValue(passwordFormParam),
	}
	response, err := a.client.AuthenticateUser(req.Context(), request)
	if err != nil {
		return a.renderError(w, "login", session, err.Error())
	}
	session.SetUserID(response.Username)
	session.SetUserInfoClaim("tenant_id", response.TenantId)
	session.SetUserInfoClaim("email", response.EmailAddress)
	session.StoreParameter(authTimeParam, unixNow())
	return goidc.StatusSuccess, nil
}

func (a *Authenticator) createUserSession(w http.ResponseWriter, req *http.Request, authnSession *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	ctx := req.Context()
	sessionID := uuid.NewString()
	if id := authnSession.StoredParameter(userSessionIDParam); id != nil {
		sessionID = id.(string)
	}
	err := a.sessionStore.Put(ctx, sessionID, &session.User{
		ID:       sessionID,
		Subject:  authnSession.Subject,
		AuthTime: authnSession.StoredParameter(authTimeParam).(int),
	})
	if err != nil {
		slog.ErrorContext(ctx, "Error creating user session", slog.Any(logger.ErrorKey, err))

		return goidc.StatusFailure, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     userSessionIDCookie,
		Value:    sessionID,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	return goidc.StatusSuccess, nil
}

func (a *Authenticator) grantConsent(w http.ResponseWriter, req *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	ctx := req.Context()

	if err := req.ParseForm(); err != nil {
		slog.ErrorContext(ctx, "Error parsing form", slog.Any(logger.ErrorKey, err))

		return goidc.StatusFailure, err
	}

	isConsented := req.PostFormValue(consentFormParam)
	if isConsented == "" {
		return a.renderPage(w, "consent", session)
	}
	if isConsented != "true" {
		return goidc.StatusFailure, errors.New("consent not granted")
	}
	return goidc.StatusSuccess, nil
}

func (a *Authenticator) finishFlow(req *http.Request, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	ctx := req.Context()

	session.GrantScopes(session.Scopes)
	session.GrantResources(session.Resources)
	session.GrantAuthorizationDetails(session.AuthDetails)

	session.SetIDTokenClaimAuthTime(session.StoredParameter(authTimeParam).(int))
	session.SetIDTokenClaimACR(goidc.ACRMaceIncommonIAPSilver)

	request := &protobuf.GetUserRequest{
		TenantId: session.AdditionalUserInfoClaims["tenant_id"].(string),
		Username: session.Subject,
	}
	response, err := a.client.GetUser(ctx, request)
	if err != nil {
		slog.ErrorContext(ctx, "Error retrieving user", slog.Any(logger.ErrorKey, err))

		return goidc.StatusFailure, err
	}
	user := response.User

	slog.InfoContext(ctx, "Adding claims based on the claims parameter")

	if session.Claims != nil {
		slog.DebugContext(ctx, "Adding ACR claims")

		addClaim(session, goidc.ClaimACR)

		slog.DebugContext(ctx, "Adding name claim")

		addClaimValue(session, goidc.ClaimName, fmt.Sprintf("%s %s", user.FirstName, user.LastName))

		slog.DebugContext(ctx, "Adding email claim")

		addClaimValue(session, goidc.ClaimEmail, user.EmailAddress)

		slog.DebugContext(ctx, "Adding email_verified claim")

		addClaimValue(session, goidc.ClaimEmailVerified, true)

		slog.DebugContext(ctx, "Adding phone_number claim")

		addClaimValue(session, goidc.ClaimPhoneNumber, user.PrimaryTelephone)

		slog.DebugContext(ctx, "Adding phone_number_verified claim")

		addClaimValue(session, goidc.ClaimPhoneNumberVerified, true)

		slog.DebugContext(ctx, "Adding address claim")

		addClaimValue(session, goidc.ClaimAddress, map[string]any{
			"street_address": user.Street,
			"locality":       user.Locality,
			"region":         user.Region,
			"postal_code":    user.PostalCode,
			"country":        user.Country,
		})
	}

	slog.InfoContext(ctx, "Adding claims based on scope")

	setClaimFn := session.SetUserInfoClaim
	if session.ResponseType == goidc.ResponseTypeIDToken {
		setClaimFn = session.SetIDTokenClaim
	}

	if strings.Contains(session.Scopes, goidc.ScopeEmail.ID) {
		setClaimFn(goidc.ClaimEmail, user.EmailAddress)
		setClaimFn(goidc.ClaimEmailVerified, true)
	}
	if strings.Contains(session.Scopes, goidc.ScopePhone.ID) {
		setClaimFn(goidc.ClaimPhoneNumber, user.PrimaryTelephone)
		setClaimFn(goidc.ClaimPhoneNumberVerified, true)
	}
	if strings.Contains(session.Scopes, goidc.ScopeAddress.ID) {
		setClaimFn(goidc.ClaimAddress, map[string]any{
			"street_address": user.Street,
			"locality":       user.Locality,
			"region":         user.Region,
			"postal_code":    user.PostalCode,
			"country":        user.Country,
		})
	}
	if strings.Contains(session.Scopes, goidc.ScopeProfile.ID) {
		// setClaimFunc(goidc.ClaimWebsite, "https://example.com")
		// setClaimFunc(goidc.ClaimZoneInfo, "America/Sao_Paulo")
		// setClaimFunc(goidc.ClaimBirthdate, "1990-01-01")
		// setClaimFunc(goidc.ClaimGender, "male")
		// setClaimFunc(goidc.ClaimProfile, "https://example.com/johndoe")
		setClaimFn(goidc.ClaimPreferredUsername, user.Username)
		setClaimFn(goidc.ClaimGivenName, user.FirstName)
		// setClaimFunc(goidc.ClaimMiddleName, "Michael")
		// setClaimFunc(goidc.ClaimLocale, "en-US")
		// setClaimFunc(goidc.ClaimPicture, "https://example.com/johndoe/profile.jpg")
		setClaimFn(goidc.ClaimUpdatedAt, unixNow())
		setClaimFn(goidc.ClaimName, fmt.Sprintf("%s %s", user.FirstName, user.LastName))
		// setClaimFn(goidc.ClaimNickname, "Johnny")
		setClaimFn(goidc.ClaimFamilyName, user.LastName)
	}
	return goidc.StatusSuccess, nil
}

type AuthenticationPage struct {
	Subject           string
	BaseURL           string
	CallbackID        string
	LogoURI           string
	PolicyURI         string
	TermsOfServiceURI string
	Error             string
	Session           map[string]any
}

func (a *Authenticator) renderPage(w http.ResponseWriter, templateName string, session *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	params := AuthenticationPage{
		Subject:    session.Subject,
		BaseURL:    a.issuer,
		CallbackID: session.CallbackID,
		Session:    sessionToMap(session),
	}

	logoURI := session.StoredParameter(logoURIParam)
	if logoURI != nil {
		params.LogoURI = logoURI.(string)
	}

	policyURI := session.StoredParameter(policyURIParam)
	if policyURI != nil {
		params.PolicyURI = policyURI.(string)
	}

	termsOfServiceURI := session.StoredParameter(termsOfServiceURIParam)
	if termsOfServiceURI != nil {
		params.TermsOfServiceURI = termsOfServiceURI.(string)
	}

	w.WriteHeader(http.StatusOK)
	_ = a.template.ExecuteTemplate(w, templateName+".html.tmpl", params)
	return goidc.StatusInProgress, nil
}

func (a *Authenticator) renderError(w http.ResponseWriter, templateName string, session *goidc.AuthnSession, err string) (goidc.AuthnStatus, error) {
	params := AuthenticationPage{
		Subject:    session.Subject,
		BaseURL:    "", // Issuer = http://auth.local
		CallbackID: session.CallbackID,
		Error:      err,
		Session:    sessionToMap(session),
	}

	logoURI := session.StoredParameter(logoURIParam)
	if logoURI != nil {
		params.LogoURI = logoURI.(string)
	}

	policyURI := session.StoredParameter(policyURIParam)
	if policyURI != nil {
		params.PolicyURI = policyURI.(string)
	}

	termsOfServiceURI := session.StoredParameter(termsOfServiceURIParam)
	if termsOfServiceURI != nil {
		params.TermsOfServiceURI = termsOfServiceURI.(string)
	}

	w.WriteHeader(http.StatusOK)
	_ = a.template.ExecuteTemplate(w, "templates/"+templateName+".gohtml", params)
	return goidc.StatusInProgress, nil
}
