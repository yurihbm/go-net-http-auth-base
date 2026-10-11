package providers

import "time"

func SetOAuthHTTPTimeout(d time.Duration) func() {
	previous := oauthHTTPTimeout
	oauthHTTPTimeout = d
	return func() { oauthHTTPTimeout = previous }
}
