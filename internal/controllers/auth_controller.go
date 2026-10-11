package controllers

import (
	"net/http"
	"slices"
	"time"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
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

type AuthController struct {
	authService       domain.AuthService
	auditService      domain.AuditService
	isSecureCookie    bool
	callbackAllowList []string
}

var _ Controller = (*AuthController)(nil)

func NewAuthController(
	authService domain.AuthService,
	auditService domain.AuditService,
	isSecureCookie bool,
	callbackAllowList []string,
) *AuthController {
	return &AuthController{
		authService,
		auditService,
		isSecureCookie,
		callbackAllowList,
	}
}

func (c *AuthController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /auth/login", c.Login)
	router.HandleFunc("POST "+api.RefreshTokenCookiePath, c.RefreshToken)
	router.HandleFunc("POST /auth/logout", c.Logout)
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
	c.deleteAuthCookies(w)

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
	providerName := domain.OAuthProviderName(r.PathValue("provider"))
	isValidProvider := domain.OAuthProviderName.IsValid(providerName)
	if !isValidProvider {
		api.HandleError(r.Context(), w, ErrInvalidOAuthProvider)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	if !slices.Contains(c.callbackAllowList, redirectURI) || redirectURI == "" {
		api.HandleError(r.Context(), w, ErrInvalidRedirectURI)
		return
	}

	state, err := c.authService.GenerateToken(r.Context(), domain.GenerateTokenDTO{
		Audience: domain.TokenAudienceOAuthState,
		Subject:  string(providerName),
		Payload: map[string]string{
			"redirect_uri": redirectURI,
		},
	})

	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	authURL, err := c.authService.GetOAuthProviderAuthURL(r.Context(), providerName, state)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (c *AuthController) OAuthProviderCallback(w http.ResponseWriter, r *http.Request) {
	providerName := domain.OAuthProviderName(r.PathValue("provider"))
	isValidProvider := providerName.IsValid()
	if !isValidProvider {
		api.HandleError(r.Context(), w, ErrInvalidOAuthProvider)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		details := map[string]string{}
		if state == "" {
			details["state"] = "state is required"
		}
		if code == "" {
			details["code"] = "code is required"
		}
		api.HandleError(r.Context(), w,
			domain.NewValidationError(
				"auth.provider_callback.missingParams",
				details,
			),
		)
		return
	}

	result, err := c.authService.OAuthLogin(r.Context(), domain.OAuthLoginDTO{
		Provider: providerName,
		State:    state,
		Code:     code,
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

	c.setAuthCookies(w, result.Tokens)

	http.Redirect(w, r, result.RedirectURI, http.StatusFound)
}

func (c *AuthController) setAuthCookies(w http.ResponseWriter, tokens domain.AuthTokens) {
	isSecure := c.isSecureCookie

	http.SetCookie(w, &http.Cookie{
		Name:     api.AccessTokenCookieName,
		Value:    tokens.AccessToken,
		Path:     api.AccessTokenCookiePath,
		HttpOnly: true,
		Expires:  time.Time.Add(time.Now(), domain.TokenExpirationAccess),
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecure,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     api.RefreshTokenCookieName,
		Value:    tokens.RefreshToken,
		Path:     api.RefreshTokenCookiePath,
		HttpOnly: true,
		Expires:  time.Time.Add(time.Now(), domain.TokenExpirationRefresh),
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
		Expires:  time.Unix(0, 0),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     api.RefreshTokenCookieName,
		Value:    "",
		Path:     api.RefreshTokenCookiePath,
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})
}
