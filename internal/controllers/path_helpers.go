package controllers

import (
	"net/http"

	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
)

func pathUUID(r *http.Request, name, errorKey string) (string, error) {
	parsed, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return "", domain.NewValidationError(errorKey, map[string]string{name: err.Error()})
	}
	return parsed.String(), nil
}
