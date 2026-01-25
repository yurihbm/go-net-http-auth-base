package controllers

import (
	"encoding/json"
	"net/http"
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

type AuthController struct {
	authService  domain.AuthService
	usersService domain.UsersService
}

var _ Controller = (*AuthController)(nil)

func NewAuthController(
	authService domain.AuthService,
	usersService domain.UsersService,
) *AuthController {
	return &AuthController{
		authService,
		usersService,
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
	// TODO: Improve error handling for invalid JSON. Add better details (domain.ValidationError).
	if err := decoder.Decode(&dto); err != nil {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "auth.login.badRequest",
			Error:   err.Error(),
		})
		return
	}

	tokens, err := c.authService.CredentialsLogin(dto)
	if err != nil {
		api.HandleError(w, err)
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
		api.HandleError(w,
			domain.NewUnauthorizedError(
				"auth.refresh.missingRefreshToken",
			),
		)
		return
	}

	tokens, err := c.authService.RefreshToken(domain.RefreshTokenDTO{
		RefreshToken: refreshToken.Value,
	})
	if err != nil {
		api.HandleError(w, err)
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
		api.HandleError(w, ErrInvalidOAuthProvider)
		return
	}

	state, err := c.authService.GenerateToken(domain.GenerateTokenDTO{
		Audience: domain.TokenAudienceOAuthState,
		Subject:  string(providerName),
		Payload: map[string]string{
			"redirect_uri": r.URL.Query().Get("redirect_uri"),
		},
	})

	if err != nil {
		api.HandleError(w, err)
		return
	}

	authURL, err := c.authService.GetOAuthProviderAuthURL(providerName, state)
	if err != nil {
		api.HandleError(w, err)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (c *AuthController) OAuthProviderCallback(w http.ResponseWriter, r *http.Request) {
	providerName := domain.OAuthProviderName(r.PathValue("provider"))
	isValidProvider := providerName.IsValid()
	if !isValidProvider {
		api.HandleError(w, ErrInvalidOAuthProvider)
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
		api.HandleError(w,
			domain.NewValidationError(
				"auth.provider_callback.missingParams",
				details,
			),
		)
		return
	}

	tokenData, err := c.authService.VerifyToken(domain.VerifyTokenDTO{
		Token:    state,
		Audience: domain.TokenAudienceOAuthState,
	})
	if err != nil {
		api.HandleError(w, err)
		return
	}

	redirectURI, ok := tokenData.Payload.(map[string]any)["redirect_uri"].(string)
	if !ok {
		api.HandleError(w,
			domain.NewValidationError(
				"auth.providerCallback.invalidStatePayload",
				map[string]string{
					"redirect_uri": "invalid redirect_uri in state payload",
				},
			),
		)
		return
	}

	userInfo, err := c.authService.GetOAuthProviderUserInfo(
		r.Context(),
		providerName,
		code,
	)
	if err != nil {
		api.HandleError(w, err)
		return
	}

	if userInfo.ID == "" || userInfo.Email == "" {
		details := map[string]string{}
		if userInfo.ID == "" {
			details["id"] = "user ID is required"
		}
		if userInfo.Email == "" {
			details["email"] = "user email is required"
		}
		api.HandleError(w,
			domain.NewValidationError(
				"auth.providerCallback.invalidUserInfo",
				details,
			),
		)
		return
	}

	userOAuthProvider, _ := c.authService.GetUserOAuthProvider(domain.GetUserOAuthProviderDTO{
		Provider:       providerName,
		ProviderUserID: userInfo.ID,
	})

	var authenticatedUser *domain.User

	// Case 1: Provider account is already used
	if userOAuthProvider != nil {
		authenticatedUser, err = c.usersService.GetByUUID(userOAuthProvider.UserUUID)
		if err != nil {
			api.HandleError(w, err)
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
				Provider:       providerName,
				ProviderUserID: userInfo.ID,
				ProviderEmail:  userInfo.Email,
			})
			if err != nil {
				api.HandleError(w, err)
				return
			}
		} else {
			// Case 3: Provider is not used and there is no user with email (create user and link)
			// TODO: Use transaction here to avoid orphaned OAuthProvider records
			newUser, err := c.usersService.Create(domain.CreateUserDTO{
				Name:     userInfo.Name,
				Email:    userInfo.Email,
				Password: "",
			})
			if err != nil {
				api.HandleError(w, err)
				return
			}

			_, err = c.authService.AddUserOAuthProvider(domain.AddUserOAuthProviderDTO{
				UserUUID:       newUser.UUID,
				Provider:       providerName,
				ProviderUserID: userInfo.ID,
				ProviderEmail:  userInfo.Email,
			})
			if err != nil {
				api.HandleError(w, err)
				// TODO: Remove this when transaction is implemented
				c.usersService.Delete(newUser.UUID) // Rollback user creation
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
		api.HandleError(w, err)
		return
	}

	refreshToken, err := c.authService.GenerateToken(domain.GenerateTokenDTO{
		Subject:  authenticatedUser.UUID,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		api.HandleError(w, err)
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
