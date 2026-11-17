package api

import (
	"encoding/json"
	"errors"
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
// request. The IP comes from r.RemoteAddr (port stripped), like the rate
// limiter: X-Forwarded-For and X-Real-IP are set by the client unless a trusted
// proxy overwrites them, so they are ignored.
func GetClientMetadata(r *http.Request) (ip string, userAgent string) {
	userAgent = r.Header.Get("User-Agent")

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		return
	}
	ip = host
	return
}
