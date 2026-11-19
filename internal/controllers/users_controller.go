package controllers

import (
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/shared"
)

type UsersController struct {
	userService          domain.UsersService
	pendingSignupService domain.PendingSignupService
	auditService         domain.AuditService
	authMiddleware       middlewares.HandlerMiddleware
	stepUpMiddleware     middlewares.HandlerMiddleware
	isSecureCookie       bool
}

var _ Controller = (*UsersController)(nil)

func NewUsersController(
	service domain.UsersService,
	pendingSignupService domain.PendingSignupService,
	auditService domain.AuditService,
	authMiddleware middlewares.HandlerMiddleware,
	stepUpMiddleware middlewares.HandlerMiddleware,
	isSecureCookie bool,
) *UsersController {
	return &UsersController{
		userService:          service,
		pendingSignupService: pendingSignupService,
		auditService:         auditService,
		authMiddleware:       authMiddleware,
		stepUpMiddleware:     stepUpMiddleware,
		isSecureCookie:       isSecureCookie,
	}
}

func (c *UsersController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /users", c.CreateUser)
	router.HandleFunc("POST /users/revert-email-change", c.RevertEmailChange)
	router.HandleFunc("GET /users/me", c.authMiddleware.Use(c.GetMe))
	router.HandleFunc("POST /users/me/email", c.authMiddleware.Use(c.stepUpMiddleware.Use(c.RequestEmailChange)))
	router.HandleFunc("POST /users/me/email/confirm", c.authMiddleware.Use(c.ConfirmEmailChange))
	router.HandleFunc("GET /users/{uuid}", c.authMiddleware.Use(c.GetUserByUUID))
	router.HandleFunc("PUT /users/{uuid}", c.authMiddleware.Use(c.UpdateUser))
	router.HandleFunc("DELETE /users/{uuid}", c.authMiddleware.Use(c.stepUpMiddleware.Use(c.DeleteUser)))
}

// @Summary		Start a sign-up
// @Description	Emails a 6-digit code to the address and sets the HttpOnly `pending_signup` cookie (`__Host-pending_signup` outside development, valid for 1 hour). No account exists until POST /auth/signup/verify succeeds in the same browser. One email per address every 60 seconds and 5 per hour.
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.CreateUserDTO	true	"User data"
// @Success		202		{object}	api.ResponseBody[any]	"Code sent (user.create.pending)"
// @Failure		400		{object}	api.ResponseBody[any]	"Validation error"
// @Failure		409		{object}	api.ResponseBody[any]	"Email already in use (users.email.conflict)"
// @Failure		429		{object}	api.ResponseBody[any]	"Too many emails to this address (auth.email.sendLimit)"
// @Failure		500		{object}	api.ResponseBody[any]	"Internal server error, or the email could not be sent (auth.signup.sendFailed)"
// @Router			/users [post]
func (c *UsersController) CreateUser(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.CreateUserDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	pendingUUID, err := c.pendingSignupService.StartCredentials(r.Context(), dto)
	if err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			ActorUUID:     actorUUID(r),
			Action:        domain.AuditActionSignupRequest,
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
		Action:       domain.AuditActionSignupRequest,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: "",
		Status:       domain.AuditStatusSuccess,
	})

	api.SetPendingSignupCookie(w, pendingUUID, c.isSecureCookie)
	api.WriteJSONResponse(w, http.StatusAccepted, api.ResponseBody[any]{
		Message: "user.create.pending",
	})
}

// @Summary		Request an email change
// @Description	Emails a 6-digit code to the new address; the email only changes after POST /users/me/email/confirm succeeds in the same session. One email per address every 60 seconds and 5 per hour, and one request per session every 60 seconds. Requires the `access_token` cookie set by POST /auth/login and a recent step-up (POST /auth/step-up, then POST /auth/step-up/verify).
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.RequestEmailChangeDTO	true	"New email address"
// @Success		202		{object}	api.ResponseBody[any]			"Code sent"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]			"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]			"Step-up required (auth.stepUp.required)"
// @Failure		409		{object}	api.ResponseBody[any]			"Conflict"
// @Failure		429		{object}	api.ResponseBody[any]			"Cooldown (users.emailChange.cooldown) or too many emails to the address (auth.email.sendLimit)"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error, or the email could not be sent (users.emailChange.sendFailed)"
// @Router			/users/me/email [post]
func (c *UsersController) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.RequestEmailChangeDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	actor := actorFromRequest(r)
	_, sessionUUID := sessionFromRequest(r)
	if err := c.userService.RequestEmailChange(r.Context(), actor, sessionUUID, dto.Email); err != nil {
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
// @Description	Applies the new email with the code sent to it by POST /users/me/email, marks it as verified, signs out every device and clears the auth cookies. Only the session that requested the change can confirm it. Requires the `access_token` cookie set by POST /auth/login.
// @Tags			users
// @Accept			json
// @Produce		json
// @Param			body	body		domain.ConfirmEmailChangeDTO	true	"Code"
// @Success		200		{object}	api.ResponseBody[domain.User]	"Email changed"
// @Failure		400		{object}	api.ResponseBody[any]			"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]			"Invalid code (users.emailChange.invalidCode), no active challenge for this session (users.emailChange.noChallenge) or stale request (users.emailChange.staleToken)"
// @Failure		404		{object}	api.ResponseBody[any]			"Not found"
// @Failure		409		{object}	api.ResponseBody[any]			"Conflict, or locked after a recent change (users.emailChange.locked)"
// @Failure		429		{object}	api.ResponseBody[any]			"Too many failed codes for the address in 24 hours (auth.email.codeLocked)"
// @Failure		500		{object}	api.ResponseBody[any]			"Internal server error"
// @Router			/users/me/email/confirm [post]
func (c *UsersController) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.ConfirmEmailChangeDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	actor := actorFromRequest(r)
	_, sessionUUID := sessionFromRequest(r)
	user, err := c.userService.ConfirmEmailChange(r.Context(), actor, sessionUUID, dto.Code)
	if err != nil {
		reason := err.Error()
		auditLog(r, c.auditService, domain.CreateAuditLogDTO{
			ActorUUID:     actorUUID(r),
			Action:        domain.AuditActionEmailChange,
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

	user, err := c.userService.RevertEmailChange(r.Context(), dto.Token)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	auditLog(r, c.auditService, domain.CreateAuditLogDTO{
		Action:       domain.AuditActionEmailChangeRevert,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: user.UUID,
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
