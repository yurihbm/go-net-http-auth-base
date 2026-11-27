package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"
)

func TestHandleError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedBody   api.ResponseBody[any]
	}{
		{
			name:           "NilError",
			err:            nil,
			expectedStatus: http.StatusOK,
			expectedBody:   api.ResponseBody[any]{},
		},
		{
			name:           "NotFoundError",
			err:            domain.NewNotFoundError("resource.notFound"),
			expectedStatus: http.StatusNotFound,
			expectedBody: api.ResponseBody[any]{
				Error: "resource.notFound",
			},
		},
		{
			name: "ValidationError",
			err: domain.NewValidationError("validation.failed", map[string]string{
				"field": "required",
			}),
			expectedStatus: http.StatusBadRequest,
			expectedBody: api.ResponseBody[any]{
				Error: "validation.failed",
				Details: map[string]string{
					"field": "required",
				},
			},
		},
		{
			name:           "ConflictError",
			err:            domain.NewConflictError("resource.conflict"),
			expectedStatus: http.StatusConflict,
			expectedBody: api.ResponseBody[any]{
				Error: "resource.conflict",
			},
		},
		{
			name:           "UnauthorizedError",
			err:            domain.NewUnauthorizedError("auth.unauthorized"),
			expectedStatus: http.StatusUnauthorized,
			expectedBody: api.ResponseBody[any]{
				Error: "auth.unauthorized",
			},
		},
		{
			name:           "ForbiddenError",
			err:            domain.NewForbiddenError("auth.forbidden"),
			expectedStatus: http.StatusForbidden,
			expectedBody: api.ResponseBody[any]{
				Error: "auth.forbidden",
			},
		},
		{
			name:           "TooManyRequestsError",
			err:            domain.NewTooManyRequestsError("auth.stepUp.cooldown"),
			expectedStatus: http.StatusTooManyRequests,
			expectedBody: api.ResponseBody[any]{
				Error: "auth.stepUp.cooldown",
			},
		},
		{
			name:           "InternalServerError",
			err:            domain.NewInternalServerError("internal.error", errors.New("db failure")),
			expectedStatus: http.StatusInternalServerError,
			expectedBody: api.ResponseBody[any]{
				Error: "internal.error",
			},
		},
		{
			name:           "GenericError",
			err:            errors.New("some unexpected error"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody: api.ResponseBody[any]{
				Error: "internalServerError",
			},
		},
		{
			name: "WrappedErrorMatchesFirstDeclaredTypeInChain",
			err: domain.NewInternalServerError("internal.error", domain.NewValidationError(
				"validation.failed",
				map[string]string{"field": "required"},
			)),
			expectedStatus: http.StatusBadRequest,
			expectedBody: api.ResponseBody[any]{
				Error: "validation.failed",
				Details: map[string]string{
					"field": "required",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx := context.WithValue(
				context.Background(),
				shared.RequestContextDataKey,
				&shared.RequestContextData{},
			)

			api.HandleError(ctx, w, tt.err)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response api.ResponseBody[any]
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.err != nil {
				ctxData := ctx.Value(shared.RequestContextDataKey).(*shared.RequestContextData)
				assert.NotEmpty(t, ctxData.Error)
			}
			assert.Equal(t, tt.expectedBody.Error, response.Error)
			assert.Equal(t, tt.expectedBody.Details, response.Details)
		})
	}
}

func TestRecordError(t *testing.T) {
	newCtx := func() (context.Context, *shared.RequestContextData) {
		data := &shared.RequestContextData{}
		return context.WithValue(context.Background(), shared.RequestContextDataKey, data), data
	}

	t.Run("success - records the error", func(t *testing.T) {
		ctx, data := newCtx()
		err := errors.New("boom")

		api.RecordError(ctx, err)

		assert.Same(t, err, data.Error)
	})

	t.Run("success - unwraps internal server error to its cause", func(t *testing.T) {
		ctx, data := newCtx()
		cause := errors.New("db failure")

		api.RecordError(ctx, domain.NewInternalServerError("internal.error", cause))

		assert.Same(t, cause, data.Error)
	})

	t.Run("success - no-op without request context data", func(t *testing.T) {
		assert.NotPanics(t, func() {
			api.RecordError(context.Background(), errors.New("boom"))
		})
	})
}
