package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
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
			err:            domain.NewNotFoundError("resource.not_found"),
			expectedStatus: http.StatusNotFound,
			expectedBody: api.ResponseBody[any]{
				Error: "resource.not_found",
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
			name:           "InternalServerError",
			err:            domain.NewInternalServerError("internal.error"),
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
				Error: "internal.server_error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			api.HandleError(w, tt.err)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response api.ResponseBody[any]
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedBody.Error, response.Error)
			assert.Equal(t, tt.expectedBody.Details, response.Details)
		})
	}
}