package api

import (
	"context"
	"errors"
	"net/http"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"
)

func HandleError(ctx context.Context, w http.ResponseWriter, err error) {
	if err == nil {
		WriteJSONResponse(w, http.StatusOK, ResponseBody[any]{})
		return
	}

	RecordError(ctx, err)

	var (
		statusCode = http.StatusInternalServerError
		message    = "internalServerError"
		details    map[string]string
	)

	if notFoundErr, ok := errors.AsType[*domain.NotFoundError](err); ok {
		statusCode = http.StatusNotFound
		message = notFoundErr.Error()
	} else if validationErr, ok := errors.AsType[*domain.ValidationError](err); ok {
		statusCode = http.StatusBadRequest
		message = validationErr.Error()
		details = validationErr.Details()
	} else if conflictErr, ok := errors.AsType[*domain.ConflictError](err); ok {
		statusCode = http.StatusConflict
		message = conflictErr.Error()
	} else if unauthorizedErr, ok := errors.AsType[*domain.UnauthorizedError](err); ok {
		statusCode = http.StatusUnauthorized
		message = unauthorizedErr.Error()
	} else if forbiddenErr, ok := errors.AsType[*domain.ForbiddenError](err); ok {
		statusCode = http.StatusForbidden
		message = forbiddenErr.Error()
	} else if tooManyRequestsErr, ok := errors.AsType[*domain.TooManyRequestsError](err); ok {
		statusCode = http.StatusTooManyRequests
		message = tooManyRequestsErr.Error()
	} else if internalServerErr, ok := errors.AsType[*domain.InternalServerError](err); ok {
		statusCode = http.StatusInternalServerError
		message = internalServerErr.Error()
	}

	WriteJSONResponse(w, statusCode, ResponseBody[any]{
		Error:   message,
		Details: details,
	})
}

func RecordError(ctx context.Context, err error) {
	reqContextData, ok := ctx.Value(shared.RequestContextDataKey).(*shared.RequestContextData)
	if !ok {
		return
	}

	if internalServerErr, ok := errors.AsType[*domain.InternalServerError](err); ok {
		err = internalServerErr.Unwrap()
	}
	reqContextData.Error = err
}
