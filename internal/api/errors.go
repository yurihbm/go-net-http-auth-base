package api

import (
	"errors"
	"net/http"

	"go-net-http-auth-base/internal/domain"
)

func HandleError(w http.ResponseWriter, err error) {
	if err == nil {
		WriteJSONResponse(w, http.StatusOK, ResponseBody[any]{})
		return
	}

	var (
		statusCode = http.StatusInternalServerError
		message    = "internalServerError"
		details    map[string]string
	)

	var notFoundErr *domain.NotFoundError
	var validationErr *domain.ValidationError
	var conflictErr *domain.ConflictError
	var unauthorizedErr *domain.UnauthorizedError
	var internalServerErr *domain.InternalServerError

	if errors.As(err, &notFoundErr) {
		statusCode = http.StatusNotFound
		message = notFoundErr.Error()
	}

	if errors.As(err, &validationErr) {
		statusCode = http.StatusBadRequest
		message = validationErr.Error()
		details = validationErr.Details()
	}

	if errors.As(err, &conflictErr) {
		statusCode = http.StatusConflict
		message = conflictErr.Error()
	}

	if errors.As(err, &unauthorizedErr) {
		statusCode = http.StatusUnauthorized
		message = unauthorizedErr.Error()
	}

	if errors.As(err, &internalServerErr) {
		statusCode = http.StatusInternalServerError
		message = internalServerErr.Error()
	}

	WriteJSONResponse(w, statusCode, ResponseBody[any]{
		Error:   message,
		Details: details,
	})
}
