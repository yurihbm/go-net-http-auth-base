package api

import (
	"net/http"

	"go-net-http-auth-base/internal/domain"
)

const (
	AccessTokenCookieName = "access_token"
	AccessTokenCookiePath = "/"

	RefreshTokenCookieName = "refresh_token"
	RefreshTokenCookiePath = "/auth/refresh"
)

const (
	OAuthNonceCookieName    = "oauth_nonce"
	OAuthVerifierCookieName = "oauth_code_verifier"

	hostCookiePrefix = "__Host-"
)

func OAuthFlowCookieName(baseName string, secure bool) string {
	if secure {
		return hostCookiePrefix + baseName
	}
	return baseName
}

func OAuthFlowCookiePath(provider domain.OAuthProviderName, secure bool) string {
	if secure {
		return "/"
	}
	return "/auth/" + string(provider) + "/callback"
}

func DeleteAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    "",
		Path:     AccessTokenCookiePath,
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		Path:     RefreshTokenCookiePath,
		HttpOnly: true,
		MaxAge:   -1,
	})
}
