package controllers

import (
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/shared"
)

type UsersController struct {
	userService      domain.UsersService
	auditService     domain.AuditService
	authMiddleware   middlewares.HandlerMiddleware
	stepUpMiddleware middlewares.HandlerMiddleware
}

var _ Controller = (*UsersController)(nil)

func NewUsersController(
	service domain.UsersService,
	auditService domain.AuditService,
	authMiddleware middlewares.HandlerMiddleware,
	stepUpMiddleware middlewares.HandlerMiddleware,
) *UsersController {
	return &UsersController{
		userService:      service,
		auditService:     auditService,
		authMiddleware:   authMiddleware,
		stepUpMiddleware: stepUpMiddleware,
	}
}

func (c *UsersController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /users", c.CreateUser)
	router.HandleFunc("POST /users/verify-email", c.VerifyEmail)
	router.HandleFunc("POST /users/resend-verification", c.ResendVerification)
	router.HandleFunc("POST /users/confirm-email-change", c.ConfirmEmailChange)
	router.HandleFunc("POST /users/revert-email-change", c.RevertEmailChange)
	router.HandleFunc("GET /users/me", c.authMiddleware.Use(c.GetMe))
	router.HandleFunc("POST /users/me/email", c.authMiddleware.Use(c.stepUpMiddleware.Use(c.RequestEmailChange)))
	router.HandleFunc("GET /users/{uuid}", c.authMiddleware.Use(c.GetUserByUUID))
	router.HandleFunc("PUT /users/{uuid}", c.authMiddleware.Use(c.UpdateUser))
	router.HandleFunc("DELETE /users/{uuid}", c.authMiddleware.Use(c.stepUpMiddleware.Use(c.DeleteUser)))
}

// @Summary		Create a user
// @Description	Creates a user and sends the verification email.
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.CreateUserDTO			true	"User data"
// @Success		201		{object}	api.ResponseBody[domain.User]	"User created"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		409		{object}	api.ResponseBody[any]			"Conflict"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/users [post]
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

// @Summary		Verify an email address
// @Description	Confirms the email using the token from the verification link.
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.VerifyEmailDTO	true	"Verification token"
// @Success		200		{object}	api.ResponseBody[any]	"Email verified"
// @Failure		400		{object}	api.ResponseBody[any]	"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		404		{object}	api.ResponseBody[any]	"Not found"
// @Failure		500		{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/users/verify-email [post]
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

// @Summary		Resend the verification email
// @Description	Always succeeds for unknown or already verified emails.
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.ResendVerificationDTO	true	"Email address"
// @Success		200		{object}	api.ResponseBody[any]			"Request accepted"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/users/resend-verification [post]
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

// @Summary		Request an email change
// @Description	Sends a confirmation link to the new address; the email only changes after POST /users/confirm-email-change. Requires the `access_token` cookie set by POST /auth/login and a recent step-up (POST /auth/step-up, then POST /auth/step-up/verify).
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.RequestEmailChangeDTO	true	"New email address"
// @Success		202		{object}	api.ResponseBody[any]			"Confirmation sent"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]			"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]			"Step-up required (auth.stepUp.required)"
// @Failure		409		{object}	api.ResponseBody[any]			"Conflict"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/users/me/email [post]
func (c *UsersController) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.RequestEmailChangeDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	actor := actorFromRequest(r)
	if err := c.userService.RequestEmailChange(r.Context(), actor, dto.Email); err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			ActorUUID:     actorUUID(r),
			Action:        domain.AuditActionEmailChangeRequest,
			ResourceType:  domain.AuditResourceUser,
			ResourceUUID:  actor.UUID,
			Status:        domain.AuditStatusFailure,
			FailureReason: &reason,
		})
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionEmailChangeRequest,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: actor.UUID,
		Status:       domain.AuditStatusSuccess,
	})

	api.WriteJSONResponse(w, http.StatusAccepted, api.ResponseBody[any]{
		Message: "user.emailChange.requested",
	})
}

// @Summary		Confirm an email change
// @Description	Applies the new email using the token from the confirmation link and marks it as verified.
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.ConfirmEmailChangeDTO	true	"Confirmation token"
// @Success		200		{object}	api.ResponseBody[domain.User]	"Email changed"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]			"Unauthorized"
// @Failure		404		{object}	api.ResponseBody[any]			"Not found"
// @Failure		409		{object}	api.ResponseBody[any]			"Conflict"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/users/confirm-email-change [post]
func (c *UsersController) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.ConfirmEmailChangeDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	user, err := c.userService.ConfirmEmailChange(r.Context(), dto.Token)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		Action:       domain.AuditActionEmailChange,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: user.UUID,
		Status:       domain.AuditStatusSuccess,
	})

	api.DeleteAuthCookies(w)
	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.User]{
		Data:    *user,
		Message: "user.emailChange.success",
	})
}

// @Summary		Revert an email change
// @Description	Restores the previous email using the token from the "it wasn't me" link, signs out every device and unlinks OAuth providers added since the change.
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.RevertEmailChangeDTO	true	"Revert token"
// @Success		200		{object}	api.ResponseBody[any]		"Email change reverted"
// @Failure		400		{object}	api.ResponseBody[any]		"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]		"Unauthorized"
// @Failure		404		{object}	api.ResponseBody[any]		"Not found"
// @Failure		409		{object}	api.ResponseBody[any]		"Conflict"
// @Failure		500		{object}	api.ResponseBody[any]		"Internal server error"
// @Router			/users/revert-email-change [post]
func (c *UsersController) RevertEmailChange(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.RevertEmailChangeDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	if err := c.userService.RevertEmailChange(r.Context(), dto.Token); err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		Action:       domain.AuditActionEmailChangeRevert,
		ResourceType: domain.AuditResourceUser,
		Status:       domain.AuditStatusSuccess,
	})

	api.DeleteAuthCookies(w)
	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[any]{
		Message: "user.emailChange.reverted",
	})
}

// @Summary		Get the authenticated user
// @Description	Requires the `access_token` cookie set by POST /auth/login.
// @Tags			users
// @Produce		json
// @Success		200	{object}	api.ResponseBody[domain.User]	"Authenticated user"
// @Failure		401	{object}	api.ResponseBody[any]			"Unauthorized"
// @Failure		404	{object}	api.ResponseBody[any]			"Not found"
// @Failure		500	{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/users/me [get]
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

// @Summary		Get a user by UUID
// @Description	Requires the `access_token` cookie set by POST /auth/login.
// @Tags			users
// @Produce		json
// @Param			uuid	path		string							true	"User UUID"
// @Success		200		{object}	api.ResponseBody[domain.User]	"User"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]			"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]			"Forbidden"
// @Failure		404		{object}	api.ResponseBody[any]			"Not found"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/users/{uuid} [get]
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

// @Summary		Update a user
// @Description	Partially updates a user. The email changes through POST /users/me/email. Requires the `access_token` cookie set by POST /auth/login.
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			uuid	path		string							true	"User UUID"
// @Param			body	body		domain.UserUpdateDTO			true	"Fields to update"
// @Success		200		{object}	api.ResponseBody[domain.User]	"User updated"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]			"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]			"Forbidden"
// @Failure		404		{object}	api.ResponseBody[any]			"Not found"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/users/{uuid} [put]
func (c *UsersController) UpdateUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.PathValue("uuid")

	dto, err := api.DecodeAndValidate[domain.UserUpdateDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	updatedUser, err := c.userService.Update(r.Context(), actorFromRequest(r), uuid, dto)
	if err != nil {
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
			Data:    *updatedUser,
			Message: "user.update.success",
		},
	)
}

// @Summary		Delete a user
// @Description	Requires the `access_token` cookie set by POST /auth/login and a recent step-up (POST /auth/step-up, then POST /auth/step-up/verify), also for admins.
// @Tags			users
// @Produce		json
// @Param			uuid	path	string	true	"User UUID"
// @Success		204		"User deleted"
// @Failure		400		{object}	api.ResponseBody[any]	"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]	"Forbidden, or step-up required (auth.stepUp.required)"
// @Failure		404		{object}	api.ResponseBody[any]	"Not found"
// @Failure		409		{object}	api.ResponseBody[any]	"Self deletion blocked during the email change lock (users.emailChange.locked)"
// @Failure		500		{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/users/{uuid} [delete]
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
