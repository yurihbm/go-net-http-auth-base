package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"

	"go-net-http-auth-base/internal/domain"

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
	return v
}()

func DecodeAndValidate[T any](r *http.Request) (T, error) {
	var v T
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, domain.NewValidationError("request.invalid",
			map[string]string{"body": err.Error()})
	}
	if dec.More() {
		return v, domain.NewValidationError("request.invalid",
			map[string]string{"body": "request body must contain exactly one JSON object"})
	}
	if err := validate.Struct(v); err != nil {
		details := make(map[string]string)
		for _, fe := range err.(validator.ValidationErrors) {
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
	default:
		return fmt.Sprintf("failed validation: %s", fe.Tag())
	}
}

// GetClientMetadata extracts the client IP address and User-Agent from the
// request. IP resolution follows the priority order:
//  1. X-Forwarded-For header (first address in the list)
//  2. X-Real-IP header
//  3. r.RemoteAddr (port stripped)
func GetClientMetadata(r *http.Request) (ip string, userAgent string) {
	userAgent = r.Header.Get("User-Agent")

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip = strings.TrimSpace(parts[0])
		return
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip = strings.TrimSpace(xri)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		return
	}
	ip = host
	return
}
