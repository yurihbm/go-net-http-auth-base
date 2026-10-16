package controllers

import (
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/shared"
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
	router.HandleFunc("POST /users/verify-email", c.VerifyEmail)
	router.HandleFunc("POST /users/resend-verification", c.ResendVerification)
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

func (c *UsersController) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.VerifyEmailDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	if err := c.userService.VerifyEmail(r.Context(), dto.Token); err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		Action:       domain.AuditActionVerifyEmail,
		ResourceType: domain.AuditResourceAuth,
		ResourceUUID: "",
		Status:       domain.AuditStatusSuccess,
	})

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "user.verifyEmail.success",
	})
}

func (c *UsersController) ResendVerification(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.ResendVerificationDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	if err := c.userService.ResendVerification(r.Context(), dto.Email); err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "user.resendVerification.success",
	})
}

func (c *UsersController) GetMe(w http.ResponseWriter, r *http.Request) {
	reqContextData, ok := r.Context().Value(shared.RequestContextDataKey).(*shared.RequestContextData)
	if !ok || reqContextData.UserUUID == "" {
		api.HandleError(r.Context(), w,
			domain.NewUnauthorizedError(
				"user.getMe.unauthorized",
			),
		)
		return
	}

	user, err := c.userService.GetByUUID(r.Context(), actorFromRequest(r), reqContextData.UserUUID)
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
	user, err := c.userService.GetByUUID(r.Context(), actorFromRequest(r), uuid)
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

	if err := c.userService.Update(r.Context(), actorFromRequest(r), uuid, dto); err != nil {
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
	if err := c.userService.Delete(r.Context(), actorFromRequest(r), uuid); err != nil {
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
