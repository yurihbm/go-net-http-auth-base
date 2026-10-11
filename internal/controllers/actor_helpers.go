package controllers

import (
	"net/http"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/shared"
)

func actorFromRequest(r *http.Request) domain.Actor {
	reqCtxData, _ := r.Context().Value(shared.RequestContextDataKey).(*shared.RequestContextData)
	if reqCtxData == nil {
		return domain.Actor{}
	}
	return domain.Actor{UUID: reqCtxData.UserUUID, Role: reqCtxData.UserRole}
}

// actorUUID returns a pointer to the authenticated user UUID from context, or
// nil when the request is unauthenticated.
func actorUUID(r *http.Request) *string {
	reqCtxData, _ := r.Context().Value(shared.RequestContextDataKey).(*shared.RequestContextData)
	if reqCtxData != nil && reqCtxData.UserUUID != "" {
		u := reqCtxData.UserUUID
		return &u
	}
	return nil
}
