package controllers

import (
	"encoding/json"
	"net/http"
	"time"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
)

type AuthController struct {
	authService domain.AuthService
}

var _ Controller = (*AuthController)(nil)

func NewAuthController(service domain.AuthService) *AuthController {
	return &AuthController{
		authService: service,
	}
}

func (c *AuthController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /auth/login", c.Login)
	router.HandleFunc("POST /auth/refresh", c.RefreshToken)
	router.HandleFunc("POST /auth/logout", c.Logout)
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
