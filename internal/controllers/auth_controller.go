package controllers

import (
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
)

var ErrInvalidOAuthProvider = domain.NewValidationError(
	"auth.providerCallback.invalidProvider",
	map[string]string{
		"provider": "invalid OAuth provider",
	},
)

var ErrInvalidRedirectURI = domain.NewValidationError(
	"auth.login.invalidRedirectUri",
	map[string]string{
		"redirect_uri": "redirect_uri is not allowed",
	},
)

var oauthProviderErrorCodes = []string{
	"access_denied",
	"invalid_request",
	"unauthorized_client",
	"unsupported_response_type",
	"invalid_scope",
	"server_error",
	"temporarily_unavailable",
}

const defaultOAuthProviderErrorCode = "access_denied"

type AuthController struct {
	authService       domain.AuthService
	auditService      domain.AuditService
	authMiddleware    middlewares.HandlerMiddleware
	isSecureCookie    bool
	callbackAllowList []string
}

var _ Controller = (*AuthController)(nil)

func NewAuthController(
	authService domain.AuthService,
	auditService domain.AuditService,
	authMiddleware middlewares.HandlerMiddleware,
	isSecureCookie bool,
	callbackAllowList []string,
) *AuthController {
	return &AuthController{
		authService,
		auditService,
		authMiddleware,
		isSecureCookie,
		callbackAllowList,
	}
}

func (c *AuthController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /auth/login", c.Login)
	router.HandleFunc("POST "+api.RefreshTokenCookiePath, c.RefreshToken)
	router.HandleFunc("POST /auth/logout", c.authMiddleware.Use(c.Logout))
	router.HandleFunc("GET /auth/{provider}/login", c.LoginWithOAuthProvider)
	router.HandleFunc("GET /auth/{provider}/callback", c.OAuthProviderCallback)
}

func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.CredentialsLoginDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	tokens, err := c.authService.CredentialsLogin(r.Context(), dto)
	if err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			Action:        domain.AuditActionLogin,
			ResourceType:  domain.AuditResourceAuth,
			ResourceUUID:  "",
			Status:        domain.AuditStatusFailure,
			FailureReason: &reason,
		})
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		Action:       domain.AuditActionLogin,
		ResourceType: domain.AuditResourceAuth,
		ResourceUUID: "",
		Status:       domain.AuditStatusSuccess,
	})

	c.setAuthCookies(w, tokens)

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "auth.login.success",
	})
}

func (c *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	userUUID, sessionUUID := sessionFromRequest(r)
	err := c.authService.Logout(r.Context(), userUUID, sessionUUID)
	c.deleteAuthCookies(w)
	if err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			ActorUUID:     actorUUID(r),
			Action:        domain.AuditActionLogout,
			ResourceType:  domain.AuditResourceAuth,
			ResourceUUID:  "",
			Status:        domain.AuditStatusFailure,
			FailureReason: &reason,
		})
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionLogout,
		ResourceType: domain.AuditResourceAuth,
		ResourceUUID: "",
		Status:       domain.AuditStatusSuccess,
	})

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "auth.logout.success",
	})
}

func (c *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := r.Cookie(api.RefreshTokenCookieName)
	if err != nil {
		api.HandleError(r.Context(), w,
			domain.NewUnauthorizedError(
				"auth.refresh.missingRefreshToken",
			),
		)
		return
	}

	tokens, err := c.authService.RefreshToken(r.Context(), domain.RefreshTokenDTO{
		RefreshToken: refreshToken.Value,
	})
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	c.setAuthCookies(w, tokens)

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "auth.refresh.success",
	})
}

func (c *AuthController) LoginWithOAuthProvider(w http.ResponseWriter, r *http.Request) {
	providerName, err := oauthProviderFromRequest(r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	if !slices.Contains(c.callbackAllowList, redirectURI) {
		api.HandleError(r.Context(), w, ErrInvalidRedirectURI)
		return
	}

	result, err := c.authService.StartOAuthLogin(r.Context(), domain.StartOAuthLoginDTO{
		Provider:    providerName,
		RedirectURI: redirectURI,
	})
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	c.setOAuthFlowCookies(w, providerName, result.Nonce, result.CodeVerifier)

	http.Redirect(w, r, result.AuthURL, http.StatusFound)
}

func (c *AuthController) OAuthProviderCallback(w http.ResponseWriter, r *http.Request) {
	providerName, err := oauthProviderFromRequest(r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	query := r.URL.Query()
	state := query.Get("state")
	code := query.Get("code")
	providerError := query.Get("error")

	if state == "" || (code == "" && providerError == "") {
		details := map[string]string{}
		if state == "" {
			details["state"] = "state is required"
		}
		if code == "" && providerError == "" {
			details["code"] = "code is required"
		}
		api.HandleError(r.Context(), w,
			domain.NewValidationError(
				"auth.providerCallback.missingParams",
				details,
			),
		)
		return
	}

	nonce := c.oauthFlowCookieValue(r, api.OAuthNonceCookieName)

	if providerError != "" {
		c.redirectOAuthProviderError(w, r, providerName, state, nonce, providerError, query.Get("error_description"))
		return
	}

	codeVerifier := c.oauthFlowCookieValue(r, api.OAuthVerifierCookieName)

	result, err := c.authService.OAuthLogin(r.Context(), domain.OAuthLoginDTO{
		Provider:     providerName,
		State:        state,
		Code:         code,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			Action:        domain.AuditActionOAuthLogin,
			ResourceType:  domain.AuditResourceAuth,
			ResourceUUID:  "",
			Status:        domain.AuditStatusFailure,
			FailureReason: &reason,
		})
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    &result.User.UUID,
		Action:       domain.AuditActionOAuthLogin,
		ResourceType: domain.AuditResourceAuth,
		ResourceUUID: result.User.UUID,
		Changes:      map[string]string{"provider": string(providerName)},
		Status:       domain.AuditStatusSuccess,
	})

	c.deleteOAuthFlowCookies(w, providerName)
	c.setAuthCookies(w, result.Tokens)

	http.Redirect(w, r, result.RedirectURI, http.StatusFound)
}

func (c *AuthController) redirectOAuthProviderError(
	w http.ResponseWriter,
	r *http.Request,
	providerName domain.OAuthProviderName,
	state string,
	nonce string,
	providerError string,
	providerErrorDescription string,
) {
	redirectURI, err := c.authService.VerifyOAuthState(r.Context(), domain.VerifyOAuthStateDTO{
		Provider: providerName,
		State:    state,
		Nonce:    nonce,
	})
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	if !slices.Contains(c.callbackAllowList, redirectURI) {
		api.HandleError(r.Context(), w, ErrInvalidRedirectURI)
		return
	}

	errorCode := defaultOAuthProviderErrorCode
	if slices.Contains(oauthProviderErrorCodes, providerError) {
		errorCode = providerError
	}

	slog.Warn("oauth provider returned an error",
		"provider", providerName,
		"error", errorCode,
		"error_description_length", len(providerErrorDescription),
	)
	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		Action:        domain.AuditActionOAuthLogin,
		ResourceType:  domain.AuditResourceAuth,
		ResourceUUID:  "",
		Status:        domain.AuditStatusFailure,
		FailureReason: &errorCode,
	})

	target, err := url.Parse(redirectURI)
	if err != nil {
		api.HandleError(r.Context(), w, ErrInvalidRedirectURI)
		return
	}
	query := target.Query()
	query.Set("error", errorCode)
	target.RawQuery = query.Encode()

	c.deleteOAuthFlowCookies(w, providerName)
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func oauthProviderFromRequest(r *http.Request) (domain.OAuthProviderName, error) {
	providerName := domain.OAuthProviderName(r.PathValue("provider"))
	if !providerName.IsValid() {
		return "", ErrInvalidOAuthProvider
	}
	return providerName, nil
}

func (c *AuthController) setOAuthFlowCookies(w http.ResponseWriter, provider domain.OAuthProviderName, nonce string, codeVerifier string) {
	maxAge := int(domain.TokenExpirationOAuthState.Seconds())
	http.SetCookie(w, c.newOAuthFlowCookie(api.OAuthNonceCookieName, nonce, provider, maxAge))
	http.SetCookie(w, c.newOAuthFlowCookie(api.OAuthVerifierCookieName, codeVerifier, provider, maxAge))
}

func (c *AuthController) deleteOAuthFlowCookies(w http.ResponseWriter, provider domain.OAuthProviderName) {
	http.SetCookie(w, c.newOAuthFlowCookie(api.OAuthNonceCookieName, "", provider, -1))
	http.SetCookie(w, c.newOAuthFlowCookie(api.OAuthVerifierCookieName, "", provider, -1))
}

func (c *AuthController) newOAuthFlowCookie(baseName string, value string, provider domain.OAuthProviderName, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     api.OAuthFlowCookieName(baseName, c.isSecureCookie),
		Value:    value,
		Path:     api.OAuthFlowCookiePath(provider, c.isSecureCookie),
		HttpOnly: true,
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
		Secure:   c.isSecureCookie,
	}
}

func (c *AuthController) oauthFlowCookieValue(r *http.Request, baseName string) string {
	cookie, err := r.Cookie(api.OAuthFlowCookieName(baseName, c.isSecureCookie))
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (c *AuthController) setAuthCookies(w http.ResponseWriter, tokens domain.AuthTokens) {
	isSecure := c.isSecureCookie

	http.SetCookie(w, &http.Cookie{
		Name:     api.AccessTokenCookieName,
		Value:    tokens.AccessToken,
		Path:     api.AccessTokenCookiePath,
		HttpOnly: true,
		MaxAge:   int(domain.TokenExpirationAccess.Seconds()),
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecure,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     api.RefreshTokenCookieName,
		Value:    tokens.RefreshToken,
		Path:     api.RefreshTokenCookiePath,
		HttpOnly: true,
		MaxAge:   int(domain.TokenExpirationRefresh.Seconds()),
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecure,
	})
}

func (c *AuthController) deleteAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     api.AccessTokenCookieName,
		Value:    "",
		Path:     api.AccessTokenCookiePath,
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     api.RefreshTokenCookieName,
		Value:    "",
		Path:     api.RefreshTokenCookiePath,
		HttpOnly: true,
		MaxAge:   -1,
	})
}
