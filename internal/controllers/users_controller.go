package controllers

import (
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
)

type UsersController struct {
	userService    domain.UsersService
	auditService   domain.AuditService
	authMiddleware middlewares.HandlerMiddleware
}

var _ Controller = (*UsersController)(nil)

func NewUsersController(
	service domain.UsersService,
	auditService domain.AuditService,
	authMiddleware middlewares.HandlerMiddleware,
) *UsersController {
	return &UsersController{
		userService:    service,
		auditService:   auditService,
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
	dto, err := api.DecodeAndValidate[domain.CreateUserDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	user, err := c.userService.Create(r.Context(), dto)
	if err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			ActorUUID:     actorUUID(r),
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
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionUserCreate,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: user.UUID,
		Status:       domain.AuditStatusSuccess,
	})

	api.WriteJSONResponse(w, http.StatusCreated, api.ResponseBody[domain.User]{
		Data:    *user,
		Message: "user.create.success",
	})
}

func (c *UsersController) GetMe(w http.ResponseWriter, r *http.Request) {
	userUUID, ok := r.Context().Value(middlewares.UserUUIDKey).(string)
	if !ok {
		api.HandleError(r.Context(), w,
			domain.NewUnauthorizedError(
				"user.getMe.unauthorized",
			),
		)
		return
	}

	user, err := c.userService.GetByUUID(r.Context(), userUUID)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.User]{
		Data:    *user,
		Message: "user.getMe.success",
	})
}

func (c *UsersController) GetUserByUUID(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	user, err := c.userService.GetByUUID(r.Context(), uuid)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.User]{
		Data:    *user,
		Message: "user.get.success",
	})
}

func (c *UsersController) UpdateUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")

	dto, err := api.DecodeAndValidate[domain.UserUpdateDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	if err := c.userService.Update(r.Context(), uuid, dto); err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			ActorUUID:     actorUUID(r),
			Action:        domain.AuditActionUserUpdate,
			ResourceType:  domain.AuditResourceUser,
			ResourceUUID:  uuid,
			Status:        domain.AuditStatusFailure,
			FailureReason: &reason,
		})
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionUserUpdate,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: uuid,
		Changes:      dto,
		Status:       domain.AuditStatusSuccess,
	})

	api.WriteJSONResponse(w, http.StatusOK,
		api.ResponseBody[domain.User]{
			Message: "user.update.success",
		},
	)
}

func (c *UsersController) DeleteUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")
	if err := c.userService.Delete(r.Context(), uuid); err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			ActorUUID:     actorUUID(r),
			Action:        domain.AuditActionUserDelete,
			ResourceType:  domain.AuditResourceUser,
			ResourceUUID:  uuid,
			Status:        domain.AuditStatusFailure,
			FailureReason: &reason,
		})
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionUserDelete,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: uuid,
		Status:       domain.AuditStatusSuccess,
	})

	w.WriteHeader(http.StatusNoContent)
}
