package controllers

import (
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/middlewares"
)

const defaultFeatureFlagsLimit = 20

type FeatureFlagsController struct {
	featureFlagsService domain.FeatureFlagsService
	auditService        domain.AuditService
	authMiddleware      middlewares.HandlerMiddleware
	adminRoleMiddleware middlewares.HandlerMiddleware
}

var _ Controller = (*FeatureFlagsController)(nil)

func NewFeatureFlagsController(
	featureFlagsService domain.FeatureFlagsService,
	auditService domain.AuditService,
	authMiddleware middlewares.HandlerMiddleware,
	adminRoleMiddleware middlewares.HandlerMiddleware,
) *FeatureFlagsController {
	return &FeatureFlagsController{
		featureFlagsService: featureFlagsService,
		auditService:        auditService,
		authMiddleware:      authMiddleware,
		adminRoleMiddleware: adminRoleMiddleware,
	}
}

func (c *FeatureFlagsController) RegisterRoutes(router *http.ServeMux) {
	router.HandleFunc("POST /feature-flags", c.authMiddleware.Use(c.adminRoleMiddleware.Use(c.CreateFeatureFlag)))
	router.HandleFunc("GET /feature-flags", c.authMiddleware.Use(c.adminRoleMiddleware.Use(c.ListFeatureFlags)))
	router.HandleFunc("GET /feature-flags/{uuid}", c.authMiddleware.Use(c.adminRoleMiddleware.Use(c.GetFeatureFlag)))
	router.HandleFunc("PATCH /feature-flags/{uuid}", c.authMiddleware.Use(c.adminRoleMiddleware.Use(c.UpdateFeatureFlag)))
	router.HandleFunc("DELETE /feature-flags/{uuid}", c.authMiddleware.Use(c.adminRoleMiddleware.Use(c.DeleteFeatureFlag)))
	router.HandleFunc("PUT /feature-flags/{uuid}/users/{userUuid}", c.authMiddleware.Use(c.adminRoleMiddleware.Use(c.AddFeatureFlagUser)))
	router.HandleFunc("DELETE /feature-flags/{uuid}/users/{userUuid}", c.authMiddleware.Use(c.adminRoleMiddleware.Use(c.RemoveFeatureFlagUser)))
}

// @Summary		Create a feature flag
// @Description	Requires the `access_token` cookie set by POST /auth/login and the admin role. The key is lowercase letters, digits and hyphens, starting with a letter or digit.
// @Tags			feature-flags
// @Accept			json
// @Produce		json
// @Param			body	body		domain.CreateFeatureFlagDTO				true	"Feature flag data"
// @Success		201		{object}	api.ResponseBody[domain.FeatureFlag]	"Feature flag created"
// @Failure		400		{object}	api.ResponseBody[any]					"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]					"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]					"Forbidden"
// @Failure		409		{object}	api.ResponseBody[any]					"Key already in use (featureFlags.key.conflict)"
// @Failure		500		{object}	api.ResponseBody[any]					"Internal server error"
// @Router			/feature-flags [post]
func (c *FeatureFlagsController) CreateFeatureFlag(w http.ResponseWriter, r *http.Request) {
	dto, err := api.DecodeAndValidate[domain.CreateFeatureFlagDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	flag, err := c.featureFlagsService.Create(r.Context(), dto)

	audit := domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionFeatureFlagCreate,
		ResourceType: domain.AuditResourceFeatureFlag,
		Changes:      dto,
	}
	if flag != nil {
		audit.ResourceUUID = flag.UUID
	}
	auditResult(r, c.auditService, audit, err)

	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusCreated, api.ResponseBody[domain.FeatureFlag]{
		Data:    *flag,
		Message: "featureFlags.create.success",
	})
}

// @Summary		List feature flags
// @Description	Lists feature flags with cursor pagination, newest first. Requires the `access_token` cookie set by POST /auth/login and the admin role.
// @Tags			feature-flags
// @Produce		json
// @Param			cursor	query		string										false	"Cursor from meta.next_cursor"
// @Param			limit	query		int											false	"Page size"	minimum(1)	maximum(100)	default(20)
// @Success		200		{object}	api.ResponseBody[[]domain.FeatureFlag]		"Feature flag page"
// @Failure		400		{object}	api.ResponseBody[any]						"Validation error (featureFlags.list.badRequest, featureFlags.invalidCursor)"
// @Failure		401		{object}	api.ResponseBody[any]						"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]						"Forbidden"
// @Failure		500		{object}	api.ResponseBody[any]						"Internal server error"
// @Router			/feature-flags [get]
func (c *FeatureFlagsController) ListFeatureFlags(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var dto domain.ListFeatureFlagsDTO

	if v := q.Get("cursor"); v != "" {
		dto.Cursor = &v
	}

	limit, err := parseLimit(q, defaultFeatureFlagsLimit, "featureFlags.list.badRequest")
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}
	dto.Limit = limit

	page, err := c.featureFlagsService.List(r.Context(), dto)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[[]domain.FeatureFlag]{
		Data:    page.Items,
		Message: "featureFlags.list.success",
		Meta: &api.ResponseMeta{
			Total:      page.Total,
			Limit:      dto.Limit,
			NextCursor: page.NextCursor,
		},
	})
}

// @Summary		Get a feature flag
// @Description	Returns the flag and the UUIDs of the users in its allow-list. Requires the `access_token` cookie set by POST /auth/login and the admin role.
// @Tags			feature-flags
// @Produce		json
// @Param			uuid	path		string											true	"Feature flag UUID"
// @Success		200		{object}	api.ResponseBody[domain.FeatureFlagDetails]		"Feature flag"
// @Failure		400		{object}	api.ResponseBody[any]							"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]							"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]							"Forbidden"
// @Failure		404		{object}	api.ResponseBody[any]							"Not found"
// @Failure		500		{object}	api.ResponseBody[any]							"Internal server error"
// @Router			/feature-flags/{uuid} [get]
func (c *FeatureFlagsController) GetFeatureFlag(w http.ResponseWriter, r *http.Request) {
	uuid, err := pathUUID(r, "uuid", "featureFlags.invalidFlagUUID")
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	details, err := c.featureFlagsService.GetByUUID(r.Context(), uuid)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.FeatureFlagDetails]{
		Data:    *details,
		Message: "featureFlags.get.success",
	})
}

// @Summary		Update a feature flag
// @Description	Partially updates the description and whether the flag is enabled for everyone. The key cannot change. Requires the `access_token` cookie set by POST /auth/login and the admin role.
// @Tags			feature-flags
// @Accept			json
// @Produce		json
// @Param			uuid	path		string									true	"Feature flag UUID"
// @Param			body	body		domain.UpdateFeatureFlagDTO				true	"Fields to update"
// @Success		200		{object}	api.ResponseBody[domain.FeatureFlag]	"Feature flag updated"
// @Failure		400		{object}	api.ResponseBody[any]					"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]					"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]					"Forbidden"
// @Failure		404		{object}	api.ResponseBody[any]					"Not found"
// @Failure		500		{object}	api.ResponseBody[any]					"Internal server error"
// @Router			/feature-flags/{uuid} [patch]
func (c *FeatureFlagsController) UpdateFeatureFlag(w http.ResponseWriter, r *http.Request) {
	uuid, err := pathUUID(r, "uuid", "featureFlags.invalidFlagUUID")
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	dto, err := api.DecodeAndValidate[domain.UpdateFeatureFlagDTO](r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	flag, err := c.featureFlagsService.Update(r.Context(), uuid, dto)
	auditResult(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionFeatureFlagUpdate,
		ResourceType: domain.AuditResourceFeatureFlag,
		ResourceUUID: uuid,
		Changes:      dto,
	}, err)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	api.WriteJSONResponse(w, http.StatusOK, api.ResponseBody[domain.FeatureFlag]{
		Data:    *flag,
		Message: "featureFlags.update.success",
	})
}

// @Summary		Delete a feature flag
// @Description	Also removes its allow-list. Requires the `access_token` cookie set by POST /auth/login and the admin role.
// @Tags			feature-flags
// @Produce		json
// @Param			uuid	path	string	true	"Feature flag UUID"
// @Success		204		"Feature flag deleted"
// @Failure		400		{object}	api.ResponseBody[any]	"Validation error"
// @Failure		401		{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		403		{object}	api.ResponseBody[any]	"Forbidden"
// @Failure		404		{object}	api.ResponseBody[any]	"Not found"
// @Failure		500		{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/feature-flags/{uuid} [delete]
func (c *FeatureFlagsController) DeleteFeatureFlag(w http.ResponseWriter, r *http.Request) {
	uuid, err := pathUUID(r, "uuid", "featureFlags.invalidFlagUUID")
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	err = c.featureFlagsService.Delete(r.Context(), uuid)
	auditResult(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionFeatureFlagDelete,
		ResourceType: domain.AuditResourceFeatureFlag,
		ResourceUUID: uuid,
	}, err)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// @Summary		Enable a feature flag for a user
// @Description	Adds the user to the flag's allow-list. Adding a user twice is not an error. Requires the `access_token` cookie set by POST /auth/login and the admin role.
// @Tags			feature-flags
// @Produce		json
// @Param			uuid		path	string	true	"Feature flag UUID"
// @Param			userUuid	path	string	true	"User UUID"
// @Success		204			"User added to the allow-list"
// @Failure		400			{object}	api.ResponseBody[any]	"Validation error"
// @Failure		401			{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		403			{object}	api.ResponseBody[any]	"Forbidden"
// @Failure		404			{object}	api.ResponseBody[any]	"Feature flag or user not found"
// @Failure		500			{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/feature-flags/{uuid}/users/{userUuid} [put]
func (c *FeatureFlagsController) AddFeatureFlagUser(w http.ResponseWriter, r *http.Request) {
	flagUUID, userUUID, err := featureFlagUserPath(r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	err = c.featureFlagsService.AddUser(r.Context(), flagUUID, userUUID)
	auditResult(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionFeatureFlagUserAdd,
		ResourceType: domain.AuditResourceFeatureFlag,
		ResourceUUID: flagUUID,
		Changes:      map[string]string{"user_uuid": userUUID},
	}, err)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// @Summary		Disable a feature flag for a user
// @Description	Removes the user from the flag's allow-list. Requires the `access_token` cookie set by POST /auth/login and the admin role.
// @Tags			feature-flags
// @Produce		json
// @Param			uuid		path	string	true	"Feature flag UUID"
// @Param			userUuid	path	string	true	"User UUID"
// @Success		204			"User removed from the allow-list"
// @Failure		400			{object}	api.ResponseBody[any]	"Validation error"
// @Failure		401			{object}	api.ResponseBody[any]	"Unauthorized"
// @Failure		403			{object}	api.ResponseBody[any]	"Forbidden"
// @Failure		404			{object}	api.ResponseBody[any]	"The user is not in the allow-list (featureFlags.users.notFound)"
// @Failure		500			{object}	api.ResponseBody[any]	"Internal server error"
// @Router			/feature-flags/{uuid}/users/{userUuid} [delete]
func (c *FeatureFlagsController) RemoveFeatureFlagUser(w http.ResponseWriter, r *http.Request) {
	flagUUID, userUUID, err := featureFlagUserPath(r)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	err = c.featureFlagsService.RemoveUser(r.Context(), flagUUID, userUUID)
	auditResult(r, c.auditService, domain.CreateAuditLogDTO{
		ActorUUID:    actorUUID(r),
		Action:       domain.AuditActionFeatureFlagUserRemove,
		ResourceType: domain.AuditResourceFeatureFlag,
		ResourceUUID: flagUUID,
		Changes:      map[string]string{"user_uuid": userUUID},
	}, err)
	if err != nil {
		api.HandleError(r.Context(), w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func featureFlagUserPath(r *http.Request) (flagUUID string, userUUID string, err error) {
	flagUUID, err = pathUUID(r, "uuid", "featureFlags.invalidFlagUUID")
	if err != nil {
		return "", "", err
	}
	userUUID, err = pathUUID(r, "userUuid", "users.invalidUserUUID")
	if err != nil {
		return "", "", err
	}
	return flagUUID, userUUID, nil
}
