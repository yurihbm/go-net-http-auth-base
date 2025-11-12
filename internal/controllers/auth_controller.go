package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
)

type AuthController struct {
	authService  domain.AuthService
	usersService domain.UsersService
}

var _ Controller = (*AuthController)(nil)

func NewAuthController(authService domain.AuthService, usersService domain.UsersService) *AuthController {
	return &AuthController{
		authService:  authService,
		usersService: usersService,
	}
}

func (c *AuthController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /auth/login", c.Login)
	router.HandleFunc("POST /auth/refresh", c.RefreshToken)
	router.HandleFunc("POST /auth/logout", c.Logout)
	router.HandleFunc("GET /auth/{provider}/login", c.LoginWithOAuthProvider)
	router.HandleFunc("GET /auth/{provider}/callback", c.OAuthProviderCallback)
}

func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	var dto domain.CredentialsLoginDTO
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&dto); err != nil {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "auth.login.bad_request",
			Error:   err.Error(),
		})
		return
	}

	tokens, err := c.authService.CredentialsLogin(dto)
	if err != nil {
		api.WriteJSONResponse(w, http.StatusUnauthorized, api.ResponseBody[any]{
			Message: "auth.login.failed",
			Error:   err.Error(),
		})
		return
	}

	c.setAuthCookies(w, tokens)

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "auth.login.success",
	})
}

func (c *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	c.deleteAuthCookies(w)

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "auth.logout.success",
	})
}

func (c *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := r.Cookie("refresh_token")
	if err != nil {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "auth.refresh.bad_request",
			Error:   err.Error(),
		})
		return
	}

	tokens, err := c.authService.RefreshToken(domain.RefreshTokenDTO{
		RefreshToken: refreshToken.Value,
	})
	if err != nil {
		api.WriteJSONResponse(w, http.StatusUnauthorized, api.ResponseBody[any]{
			Message: "auth.refresh.failed",
			Error:   err.Error(),
		})
		return
	}

	c.setAuthCookies(w, tokens)

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "auth.refresh.success",
	})
}

func (c *AuthController) LoginWithOAuthProvider(w http.ResponseWriter, r *http.Request) {
	provider := domain.OAuthProviderName(r.PathValue("provider"))
	isValidProvider := domain.OAuthProviderName.IsValid(provider)
	if !isValidProvider {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "auth.provider_login.bad_request",
			Error:   "invalid OAuth provider",
		})
		return
	}

	state, err := c.authService.GenerateToken(domain.GenerateTokenDTO{
		Audience: domain.TokenAudienceOAuthState,
		Subject:  string(provider),
		Payload: map[string]string{
			"redirect_uri": r.URL.Query().Get("redirect_uri"),
		},
	})

	if err != nil {
		api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
			Message: "auth.provider_login.failed",
			Error:   err.Error(),
		})
		return
	}

	providerConfig := config.GetOAuthConfig(provider)

	authURL := providerConfig.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (c *AuthController) OAuthProviderCallback(w http.ResponseWriter, r *http.Request) {
	provider := domain.OAuthProviderName(r.PathValue("provider"))
	isValidProvider := provider.IsValid()
	if !isValidProvider {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "auth.provider_callback.bad_request",
			Error:   "invalid OAuth provider",
		})
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "auth.provider_callback.bad_request",
			Error:   "missing state or code in query parameters",
		})
		return
	}

	tokenData, err := c.authService.VerifyToken(domain.VerifyTokenDTO{
		Token:    state,
		Audience: domain.TokenAudienceOAuthState,
	})
	if err != nil {
		api.WriteJSONResponse(w, http.StatusUnauthorized, api.ResponseBody[any]{
			Message: "auth.provider_callback.invalid_state",
			Error:   err.Error(),
		})
		return
	}

	redirectURI, ok := tokenData.Payload.(map[string]any)["redirect_uri"].(string)
	if !ok {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "auth.provider_callback.invalid_state",
			Error:   "invalid redirect_uri in state payload",
		})
		return
	}

	providerConfig := config.GetOAuthConfig(provider)
	token, err := providerConfig.Exchange(r.Context(), code)
	if err != nil {
		api.WriteJSONResponse(w, http.StatusUnauthorized, api.ResponseBody[any]{
			Message: "auth.provider_callback.token_exchange_failed",
			Error:   err.Error(),
		})
		return
	}

	userInfo, err := c.getOAuthProviderUserInfo(provider, token.AccessToken)
	if err != nil {
		api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
			Message: "auth.provider_callback.user_info_failed",
			Error:   err.Error(),
		})
		return
	}

	if userInfo.Id == "" || userInfo.Email == "" {
		api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
			Message: "auth.provider_callback.invalid_user_info",
			Error:   "missing required fields from provider",
		})
		return
	}

	userOAuthProvider, _ := c.authService.GetUserOAuthProvider(domain.GetUserOAuthProviderDTO{
		Provider:       provider,
		ProviderUserID: userInfo.Id,
	})

	var authenticatedUser *domain.User

	// Case 1: Provider account is already used
	if userOAuthProvider != nil {
		authenticatedUser, err = c.usersService.GetByUUID(userOAuthProvider.UserUUID)
		if err != nil {
			api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
				Message: "auth.provider_callback.user_not_found",
				Error:   err.Error(),
			})
			return
		}
	} else {
		// Case 2 & 3: Provider is not used, check if user exists by email
		existingUser, _ := c.usersService.GetByEmail(userInfo.Email)

		if existingUser != nil {
			// Case 2: Provider email matches existing user account (link provider)
			authenticatedUser = existingUser
			_, err := c.authService.AddUserOAuthProvider(domain.AddUserOAuthProviderDTO{
				UserUUID:       existingUser.UUID,
				Provider:       provider,
				ProviderUserID: userInfo.Id,
				ProviderEmail:  userInfo.Email,
			})
			if err != nil {
				api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
					Message: "auth.provider_callback.link_provider_failed",
					Error:   err.Error(),
				})
				return
			}
		} else {
			// Case 3: Provider is not used and there is no user with email (create user and link)
			newUser, err := c.usersService.Create(domain.CreateUserDTO{
				Name:     userInfo.Name,
				Email:    userInfo.Email,
				Password: "",
			})
			if err != nil {
				api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
					Message: "auth.provider_callback.user_creation_failed",
					Error:   err.Error(),
				})
				return
			}

			_, err = c.authService.AddUserOAuthProvider(domain.AddUserOAuthProviderDTO{
				UserUUID:       newUser.UUID,
				Provider:       provider,
				ProviderUserID: userInfo.Id,
				ProviderEmail:  userInfo.Email,
			})
			if err != nil {
				api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
					Message: "auth.provider_callback.link_provider_failed",
					Error:   err.Error(),
				})
				return
			}

			authenticatedUser = newUser
		}
	}

	accessToken, err := c.authService.GenerateToken(domain.GenerateTokenDTO{
		Subject:  authenticatedUser.UUID,
		Audience: domain.TokenAudienceAccess,
	})
	if err != nil {
		api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
			Message: "auth.provider_callback.token_generation_failed",
			Error:   err.Error(),
		})
		return
	}

	refreshToken, err := c.authService.GenerateToken(domain.GenerateTokenDTO{
		Subject:  authenticatedUser.UUID,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		api.WriteJSONResponse(w, http.StatusInternalServerError, api.ResponseBody[any]{
			Message: "auth.provider_callback.token_generation_failed",
			Error:   err.Error(),
		})
		return
	}

	c.setAuthCookies(w, domain.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

func (c *AuthController) setAuthCookies(w http.ResponseWriter, tokens domain.AuthTokens) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Time.Add(time.Now(), domain.TokenExpirationAccess),
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Time.Add(time.Now(), domain.TokenExpirationRefresh),
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})
}

func (c *AuthController) deleteAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})
}

const googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

func (c *AuthController) getOAuthProviderUserInfo(
	provider domain.OAuthProviderName,
	accessToken string,
) (*domain.OAuthProviderUserInfo, error) {
	switch provider {
	case domain.OAuthProviderGoogle:
		return c.getGoogleUserInfo(accessToken)
	default:
		return nil, errors.New("unsupported OAuth provider")
	}
}

func (c *AuthController) getGoogleUserInfo(accessToken string) (*domain.OAuthProviderUserInfo, error) {
	req, err := http.NewRequest("GET", googleUserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Println("Failed to close response body:", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch user info from Google")
	}

	var userInfo domain.OAuthProviderUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
