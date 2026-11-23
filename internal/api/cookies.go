package api

import (
	"net/http"

	"go-net-http-auth-base/internal/domain"
)

const (
	AccessTokenCookieName = "access_token"
	AccessTokenCookiePath = "/"

	RefreshTokenCookieName = "refresh_token"
	RefreshTokenCookiePath = "/auth/refresh" //nolint:gosec // G101 false positive: a URL path, not a credential
)

const (
	OAuthNonceCookieName    = "oauth_nonce"
	OAuthVerifierCookieName = "oauth_code_verifier"

	PendingSignupCookieName = "pending_signup"
	PasswordResetCookieName = "password_reset"

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

func SetPendingSignupCookie(w http.ResponseWriter, pendingUUID string, secure bool) {
	http.SetCookie(w, newPendingSignupCookie(pendingUUID, int(domain.PendingSignupTTL.Seconds()), secure))
}

func DeletePendingSignupCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, newPendingSignupCookie("", -1, secure))
}

func newPendingSignupCookie(value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     OAuthFlowCookieName(PendingSignupCookieName, secure),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   maxAge,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}
}

func SetPasswordResetCookie(w http.ResponseWriter, resetUUID string, secure bool) {
	http.SetCookie(w, newPasswordResetCookie(resetUUID, int(domain.PasswordResetTTL.Seconds()), secure))
}

func DeletePasswordResetCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, newPasswordResetCookie("", -1, secure))
}

func newPasswordResetCookie(value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     OAuthFlowCookieName(PasswordResetCookieName, secure),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   maxAge,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}
}

func SetAuthCookies(w http.ResponseWriter, tokens domain.AuthTokens, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    tokens.AccessToken,
		Path:     AccessTokenCookiePath,
		HttpOnly: true,
		MaxAge:   int(domain.TokenExpirationAccess.Seconds()),
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    tokens.RefreshToken,
		Path:     RefreshTokenCookiePath,
		HttpOnly: true,
		MaxAge:   int(domain.TokenExpirationRefresh.Seconds()),
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	})
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
