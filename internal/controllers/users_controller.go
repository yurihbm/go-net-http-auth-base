package controllers

import (
	"encoding/json"
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
)

type UsersController struct {
	userService    domain.UsersService
	authMiddleware middlewares.HandlerMiddleware
}

var _ Controller = (*UsersController)(nil)

func NewUsersController(service domain.UsersService, authMiddleware middlewares.HandlerMiddleware) *UsersController {
	return &UsersController{
		userService:    service,
		authMiddleware: authMiddleware,
	}
}

func (c *UsersController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /users", c.CreateUser)
	router.HandleFunc("GET /users/me", c.authMiddleware.Use(c.GetMe))
	router.HandleFunc("GET /users/{uuid}", c.authMiddleware.Use(c.GetUserByUUID))
	router.HandleFunc("PUT /users/{uuid}", c.authMiddleware.Use(c.UpdateUser))
	router.HandleFunc("DELETE /users/{uuid}", c.authMiddleware.Use(c.DeleteUser))
}

func (c *UsersController) CreateUser(w http.ResponseWriter, r *http.Request) {
	var dto domain.CreateUserDTO
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&dto); err != nil {
		api.WriteJSONResponse(w, http.StatusBadRequest, api.ResponseBody[any]{
			Message: "user.create.bad_request",
			Error:   err.Error(),
		})
		return
	}

	if dto.Password == "" || len(dto.Password) < 8 {
		api.HandleError(w,
			domain.NewValidationError("user.create.badRequest",
				map[string]string{
					"password": "password must be at least 8 characters long",
				},
			),
		)
		return
	}

	user, err := c.userService.Create(dto)
	if err != nil {
		api.HandleError(w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusCreated, api.ResponseBody[domain.User]{
		Data:    *user,
		Message: "user.create.success",
	})
}

func (c *UsersController) GetMe(w http.ResponseWriter, r *http.Request) {
	userUUID, ok := r.Context().Value(middlewares.UserUUIDKey).(string)
	if !ok {
		api.HandleError(w,
			domain.NewUnauthorizedError(
				"user.getMe.unauthorized",
			),
		)
		return
	}

	user, err := c.userService.GetByUUID(userUUID)
	if err != nil {
		api.HandleError(w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.User]{
		Data:    *user,
		Message: "user.getMe.success",
	})
}

func (c *UsersController) GetUserByUUID(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	user, err := c.userService.GetByUUID(uuid)
	if err != nil {
		api.HandleError(w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.User]{
		Data:    *user,
		Message: "user.get.success",
	})
}

func (c *UsersController) UpdateUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	var dto domain.UserUpdateDTO

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&dto); err != nil {
		api.WriteJSONResponse(w, http.StatusBadRequest,
			api.ResponseBody[any]{
				Message: "user.update.badRequest",
				Error:   err.Error(),
			},
		)
		return
	}

	if err := c.userService.Update(uuid, dto); err != nil {
		api.HandleError(w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK,
		api.ResponseBody[domain.User]{
			Message: "user.update.success",
		},
	)
}

func (c *UsersController) DeleteUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if err := c.userService.Delete(uuid); err != nil {
		api.HandleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
