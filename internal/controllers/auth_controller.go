package controllers

import (
	"errors"
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

const (
	defaultOAuthProviderErrorCode = "access_denied"
	oauthVerificationLimitedCode  = "verification_limited"
)

type AuthController struct {
	authService          domain.AuthService
	stepUpService        domain.StepUpService
	pendingSignupService domain.PendingSignupService
	auditService         domain.AuditService
	authMiddleware       middlewares.HandlerMiddleware
	isSecureCookie       bool
	callbackAllowList    []string
}

var _ Controller = (*AuthController)(nil)

func NewAuthController(
	authService domain.AuthService,
	stepUpService domain.StepUpService,
	pendingSignupService domain.PendingSignupService,
	auditService domain.AuditService,
	authMiddleware middlewares.HandlerMiddleware,
	isSecureCookie bool,
	callbackAllowList []string,
) *AuthController {
	return &AuthController{
		authService,
		stepUpService,
		pendingSignupService,
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
	router.HandleFunc("POST /auth/logout-others", c.authMiddleware.Use(c.LogoutOthers))
	router.HandleFunc("POST /auth/step-up", c.authMiddleware.Use(c.RequestStepUp))
	router.HandleFunc("POST /auth/step-up/verify", c.authMiddleware.Use(c.VerifyStepUp))
	router.HandleFunc("POST /auth/signup/verify", c.VerifySignup)
	router.HandleFunc("POST /auth/signup/resend", c.ResendSignup)
	router.HandleFunc("GET /auth/{provider}/login", c.LoginWithOAuthProvider)
	router.HandleFunc("GET /auth/{provider}/callback", c.OAuthProviderCallback)
}

// @Summary		Log in with credentials
// @Description	Authenticates with email and password. Sets the `access_token` and `refresh_token` cookies.
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			body	body		domain.CredentialsLoginDTO	true	"Credentials"
// @Success		200		{object}	api.ResponseBody[any]		"Logged in"
// @Failure		400		{object}	api.ResponseBody[any]		"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]		"Unauthorized"
// @Failure		500		{object}	api.ResponseBody[any]		"Internal server error"
// @Router			/auth/login [post]
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

	api.SetAuthCookies(w, tokens, c.isSecureCookie)

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "auth.login.success",
	})
}

// @Summary		Log out
// @Description	Deletes the current session and clears the auth cookies. Requires the `access_token` cookie set by POST /auth/login.
// @Tags			auth
// @Produce		json
// @Success		200	{object}	api.ResponseBody[any]	"Logged out"
// @Failure		401	{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		500	{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/auth/logout [post]
func (c *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	userUUID, sessionUUID := sessionFromRequest(r)
	err := c.authService.Logout(r.Context(), userUUID, sessionUUID)
	api.DeleteAuthCookies(w)
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

// @Summary		Log out of the other devices
// @Description	Deletes every session of the user except the current one. Requires the `access_token` cookie set by POST /auth/login.
// @Tags			auth
// @Success		204	"Other sessions deleted"
// @Failure		401	{object}	api.ResponseBody[any]	"Unauthorized, or the current session was revoked or expired"
// @Failure		500	{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/auth/logout-others [post]
func (c *AuthController) LogoutOthers(w http.ResponseWriter, r *http.Request) {
	userUUID, sessionUUID := sessionFromRequest(r)
	err := c.authService.LogoutOthers(r.Context(), userUUID, sessionUUID)
	c.auditAuth(r, domain.AuditActionLogoutOthers, err)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// @Summary		Request a step-up code
// @Description	Emails a 6-digit code to the current email address of the user. Valid for 10 minutes, one request per 60 seconds per session. Requires the `access_token` cookie set by POST /auth/login.
// @Tags			auth
// @Produce		json
// @Success		202	{object}	api.ResponseBody[any]	"Code sent"
// @Failure		401	{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		429	{object}	api.ResponseBody[any]	"Cooldown (auth.stepUp.cooldown) or too many failed codes for the user in 24 hours (auth.stepUp.userLocked)"
// @Failure		500	{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/auth/step-up [post]
func (c *AuthController) RequestStepUp(w http.ResponseWriter, r *http.Request) {
	userUUID, sessionUUID := sessionFromRequest(r)
	err := c.stepUpService.RequestCode(r.Context(), userUUID, sessionUUID)
	c.auditAuth(r, domain.AuditActionStepUpRequest, err)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusAccepted, api.ResponseBody[any]{
		Message: "auth.stepUp.codeSent",
	})
}

// @Summary		Verify a step-up code
// @Description	Elevates the current session for 5 minutes. A code allows 5 attempts. Requires the `access_token` cookie set by POST /auth/login.
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			body	body		domain.CodeDTO					true	"Code"
// @Success		200		{object}	api.ResponseBody[map[string]int64]	"Session elevated; step_up_until is a unix timestamp"
// @Failure		400		{object}	api.ResponseBody[any]					"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]					"Invalid code (auth.stepUp.invalidCode), no active challenge (auth.stepUp.noChallenge) or session revoked after too many failures (auth.stepUp.sessionRevoked, clears the auth cookies)"
// @Failure		429		{object}	api.ResponseBody[any]					"Too many failed codes for the user in 24 hours (auth.stepUp.userLocked)"
// @Failure		500		{object}	api.ResponseBody[any]					"Internal server error"
// @Router			/auth/step-up/verify [post]
func (c *AuthController) VerifyStepUp(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.CodeDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	userUUID, sessionUUID := sessionFromRequest(r)
	until, err := c.stepUpService.VerifyCode(r.Context(), userUUID, sessionUUID, dto.Code)
	c.auditAuth(r, domain.AuditActionStepUpVerify, err)
	if err != nil {
		if errors.Is(err, domain.ErrStepUpSessionRevoked) {
			api.DeleteAuthCookies(w)
		}
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[map[string]int64]{
		Data:    map[string]int64{"step_up_until": until},
		Message: "auth.stepUp.verified",
	})
}

// @Summary		Finish a sign-up
// @Description	Creates the account from the pending sign-up with the 6-digit code emailed by POST /users. Requires the `pending_signup` cookie set by POST /users, so the code only works in the browser that started the sign-up. A code allows 5 attempts and expires after 10 minutes. On success sets the `access_token` and `refresh_token` cookies and clears the `pending_signup` cookie.
// @Tags			auth
// @Accept			json
// @Produce		json
// @Param			body	body		domain.CodeDTO			true	"Code"
// @Success		201		{object}	api.ResponseBody[domain.User]	"Account created and logged in (auth.signup.success)"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]			"Wrong code (auth.signup.invalidCode), or no pending sign-up: missing cookie, expired, already used or out of attempts (auth.signup.noPending)"
// @Failure		409		{object}	api.ResponseBody[any]			"Email already in use (users.email.conflict)"
// @Failure		429		{object}	api.ResponseBody[any]			"Too many wrong codes for this address in 24 hours (auth.email.codeLocked)"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/auth/signup/verify [post]
func (c *AuthController) VerifySignup(w http.ResponseWriter, r *http.Request) {
	pendingUUID, ok := c.pendingSignupUUID(r)
	if !ok {
		api.HandleError(r.Context(), w, domain.ErrSignupNoPending)
		return
	}

	dto, err := api.DecodeAndValidate[domain.CodeDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	result, err := c.authService.CompleteSignup(r.Context(), pendingUUID, dto.Code)
	if err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			Action:        domain.AuditActionUserCreate,
			ResourceType:  domain.AuditResourceUser,
			ResourceUUID:  "",
			Status:        domain.AuditStatusFailure,
			FailureReason: &reason,
		})
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    &result.User.UUID,
		Action:       domain.AuditActionUserCreate,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: result.User.UUID,
		Status:       domain.AuditStatusSuccess,
	})

	api.DeletePendingSignupCookie(w, c.isSecureCookie)
	api.SetAuthCookies(w, result.Tokens, c.isSecureCookie)
	api.WriteJSONResponse(w, http.StatusCreated, api.ResponseBody[domain.User]{
		Data:    *result.User,
		Message: "auth.signup.success",
	})
}

// @Summary		Resend the sign-up code
// @Description	Emails a new 6-digit code for the pending sign-up and invalidates the previous one. Requires the `pending_signup` cookie set by POST /users. One email per address per 60 seconds; the sign-up itself still expires 1 hour after POST /users.
// @Tags			auth
// @Produce		json
// @Success		202	{object}	api.ResponseBody[any]	"Code sent (auth.signup.codeResent)"
// @Failure		401	{object}	api.ResponseBody[any]	"No pending sign-up (auth.signup.noPending)"
// @Failure		429	{object}	api.ResponseBody[any]	"An email went to this address in the last 60 seconds, or 5 in the last hour (auth.email.sendLimit)"
// @Failure		500	{object}	api.ResponseBody[any]	"Internal server error, or the email could not be sent (auth.signup.sendFailed)"
// @Router			/auth/signup/resend [post]
func (c *AuthController) ResendSignup(w http.ResponseWriter, r *http.Request) {
	pendingUUID, ok := c.pendingSignupUUID(r)
	if !ok {
		api.HandleError(r.Context(), w, domain.ErrSignupNoPending)
		return
	}

	if err := c.pendingSignupService.Resend(r.Context(), pendingUUID); err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusAccepted, api.ResponseBody[any]{
		Message: "auth.signup.codeResent",
	})
}

func (c *AuthController) pendingSignupUUID(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(api.OAuthFlowCookieName(api.PendingSignupCookieName, c.isSecureCookie))
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (c *AuthController) auditAuth(r *http.Request, action string, err error) {
	auditResult(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       action,
		ResourceType: domain.AuditResourceAuth,
	}, err)
}

// @Summary		Refresh the session tokens
// @Description	Rotates the refresh token. Requires the `refresh_token` cookie (path /auth/refresh) and sets new `access_token` and `refresh_token` cookies.
// @Tags			auth
// @Produce		json
// @Success		200	{object}	api.ResponseBody[any]	"Tokens refreshed"
// @Failure		401	{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		500	{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/auth/refresh [post]
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

	api.SetAuthCookies(w, tokens, c.isSecureCookie)

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "auth.refresh.success",
	})
}

// @Summary		Start an OAuth login
// @Description	Redirects to the OAuth provider and sets the OAuth flow cookies (nonce and PKCE verifier). The redirect_uri must be in the allow list.
// @Tags			auth
// @Produce		json
// @Param			provider		path	string	true	"OAuth provider"	Enums(google, microsoft, github)
// @Param			redirect_uri	query	string	true	"Allowed URI to return to after the login"
// @Success		302				"Redirect to the OAuth provider"
// @Header			302				{string}	Location				"Provider authorization URL"
// @Failure		400				{object}	api.ResponseBody[any]	"Validation error"
// @Failure		500				{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/auth/{provider}/login [get]
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

// @Summary		Finish an OAuth login
// @Description	Handles the provider callback and requires the OAuth flow cookies set by the login step. On success sets the `access_token` and `refresh_token` cookies and redirects to the redirect_uri. If the provider email is not verified, emails a one-time code, sets the `pending_signup` cookie and redirects to the redirect_uri with `?verification=required` (the frontend then posts the code to POST /auth/signup/verify); if the address hit the email send limit, redirects with `?error=verification_limited`. If the provider returned an error, redirects to the redirect_uri with `?error=<code>`.
// @Tags			auth
// @Produce		json
// @Param			provider			path	string	true	"OAuth provider"	Enums(google, microsoft, github)
// @Param			state				query	string	true	"State token issued by the login step"
// @Param			code				query	string	false	"Authorization code (required unless error is set)"
// @Param			error				query	string	false	"Error code returned by the provider"
// @Param			error_description	query	string	false	"Error description returned by the provider"
// @Success		302					"Redirect to the redirect_uri"
// @Header			302					{string}	Location				"redirect_uri, with ?verification=required, ?error=verification_limited or ?error=<code> on provider error"
// @Failure		400					{object}	api.ResponseBody[any]	"Validation error"
// @Failure		401					{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		404					{object}	api.ResponseBody[any]	"Not found"
// @Failure		409					{object}	api.ResponseBody[any]	"Conflict"
// @Failure		500					{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/auth/{provider}/callback [get]
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

	if result.VerificationLimited || result.PendingSignupUUID != "" {
		c.redirectOAuthPendingSignup(w, r, providerName, result)
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
	api.SetAuthCookies(w, result.Tokens, c.isSecureCookie)

	http.Redirect(w, r, result.RedirectURI, http.StatusFound)
}

func (c *AuthController) redirectOAuthPendingSignup(w http.ResponseWriter, r *http.Request, providerName domain.OAuthProviderName, result *domain.OAuthLoginResult) {
	target, err := url.Parse(result.RedirectURI)
	if err != nil {
		api.HandleError(r.Context(), w, ErrInvalidRedirectURI)
		return
	}
	query := target.Query()

	if result.VerificationLimited {
		reason := oauthVerificationLimitedCode
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			Action:        domain.AuditActionSignupRequest,
			ResourceType:  domain.AuditResourceAuth,
			ResourceUUID:  "",
			Changes:       map[string]string{"provider": string(providerName)},
			Status:        domain.AuditStatusFailure,
			FailureReason: &reason,
		})
		query.Set("error", oauthVerificationLimitedCode)
	} else {
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			Action:       domain.AuditActionSignupRequest,
			ResourceType: domain.AuditResourceAuth,
			ResourceUUID: "",
			Changes:      map[string]string{"provider": string(providerName)},
			Status:       domain.AuditStatusSuccess,
		})
		api.SetPendingSignupCookie(w, result.PendingSignupUUID, c.isSecureCookie)
		query.Set("verification", "required")
	}
	target.RawQuery = query.Encode()

	c.deleteOAuthFlowCookies(w, providerName)
	http.Redirect(w, r, target.String(), http.StatusFound)
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

	slog.WarnContext(r.Context(), "oauth provider returned an error",
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
