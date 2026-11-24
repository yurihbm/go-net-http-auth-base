package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"

	"github.com/go-playground/validator/v10"
)

var validate = func() *validator.Validate {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name, _, _ := strings.Cut(fld.Tag.Get("json"), ",")
		if name == "-" {
			return ""
		}
		return name
	})
	_ = v.RegisterValidation("maxbytes", func(fl validator.FieldLevel) bool {
		max, err := strconv.Atoi(fl.Param())
		return err == nil && len(fl.Field().String()) <= max
	})
	return v
}()

const maxRequestBodyBytes = 1 << 20

func DecodeAndValidate[T any](r *http.Request) (T, error) {
	var v T
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return v, domain.NewValidationError("request.invalid",
				map[string]string{"body": "request body too large"})
		}
		slog.DebugContext(r.Context(), "request body decode failed", "error", err)
		message := "request body must be valid JSON"
		if strings.HasPrefix(err.Error(), "json: unknown field") {
			message = "request body contains an unknown field"
		}
		return v, domain.NewValidationError("request.invalid",
			map[string]string{"body": message})
	}
	if dec.More() {
		return v, domain.NewValidationError("request.invalid",
			map[string]string{"body": "request body must contain exactly one JSON object"})
	}
	if err := validate.Struct(v); err != nil {
		details := make(map[string]string)
		var validationErrs validator.ValidationErrors
		errors.As(err, &validationErrs)
		for _, fe := range validationErrs {
			details[fe.Field()] = fieldErrMessage(fe)
		}
		return v, domain.NewValidationError("request.validation_failed", details)
	}
	return v, nil
}

func fieldErrMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "field is required"
	case "email":
		return "must be a valid email address"
	case "min":
		if fe.Type().Kind() == reflect.String {
			return fmt.Sprintf("must be at least %s characters long", fe.Param())
		}
		return fmt.Sprintf("must be at least %s", fe.Param())
	case "max":
		if fe.Type().Kind() == reflect.String {
			return fmt.Sprintf("must be at most %s characters long", fe.Param())
		}
		return fmt.Sprintf("must be at most %s", fe.Param())
	case "maxbytes":
		return fmt.Sprintf("must be at most %s bytes long", fe.Param())
	default:
		return fmt.Sprintf("failed validation: %s", fe.Tag())
	}
}

// GetClientMetadata extracts the client IP address and User-Agent from the
// request. The IP is the one resolved by the client IP middleware, which only
// trusts X-Forwarded-For from configured proxies (ADR-013); without it, it is
// r.RemoteAddr with the port stripped. X-Real-IP is always ignored.
func GetClientMetadata(r *http.Request) (ip string, userAgent string) {
	userAgent = r.Header.Get("User-Agent")

	ip = shared.ClientIP(r)
	return
}
