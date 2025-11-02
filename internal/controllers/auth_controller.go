package controllers

import (
	"encoding/json"
	"net/http"

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

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.AuthTokens]{
		Data:    tokens,
		Message: "auth.login.success",
	})
}

func (c *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var dto domain.RefreshTokenDTO
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&dto); err != nil {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "auth.refresh.bad_request",
			Error:   err.Error(),
		})
		return
	}

	tokens, err := c.authService.RefreshToken(domain.RefreshTokenDTO{
		RefreshToken: dto.RefreshToken,
	})
	if err != nil {
		api.WriteJSONResponse(w, http.StatusUnauthorized, api.ResponseBody[any]{
			Message: "auth.refresh.failed",
			Error:   err.Error(),
		})
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.AuthTokens]{
		Data:    tokens,
		Message: "auth.refresh.success",
	})
}
