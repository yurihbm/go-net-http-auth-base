package providers

import "time"

func SetOAuthHTTPTimeout(d time.Duration) func() {
	previous := oauthHTTPTimeout
	oauthHTTPTimeout = d
	return func() { oauthHTTPTimeout = previous }
}

func SetResendHTTPTimeout(d time.Duration) func() {
	previous := resendHTTPTimeout
	resendHTTPTimeout = d
	return func() { resendHTTPTimeout = previous }
}
