package middlewares

import (
	"errors"
	"net/http"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"
)

type StepUpMiddleware struct {
	checker domain.StepUpChecker
}

var _ HandlerMiddleware = (*StepUpMiddleware)(nil)

func NewStepUpMiddleware(checker domain.StepUpChecker) HandlerMiddleware {
	return &StepUpMiddleware{checker: checker}
}

func (m *StepUpMiddleware) Use(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqCtxData, ok := r.Context().Value(shared.RequestContextDataKey).(*shared.RequestContextData)
		if !ok {
			api.HandleError(r.Context(), w, errors.New("request context data is missing"))
			return
		}

		elevated, err := m.checker.IsElevated(r.Context(), reqCtxData.UserUUID, reqCtxData.SessionUUID)
		if err != nil {
			api.HandleError(r.Context(), w, err)
			return
		}
		if !elevated {
			api.HandleError(r.Context(), w, domain.NewForbiddenError("auth.stepUp.required"))
			return
		}

		next.ServeHTTP(w, r)
	}
}
