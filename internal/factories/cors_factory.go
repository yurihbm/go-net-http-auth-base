package factories

import (
	"os"
	"strings"

	"go-net-http-auth-base/internal/middlewares"
)

func CORSFactory() *middlewares.CORSMiddleware {
	allowedOrigins := parseAllowedOrigins()
	allowedMethods := parseAllowedMethods()
	allowedHeaders := []string{"Content-Type", "Authorization"}
	exposeHeaders := []string{}
	allowCredentials := true
	maxAge := "86400"

	return middlewares.NewCORSMiddleware(
		allowedOrigins,
		allowedMethods,
		allowedHeaders,
		exposeHeaders,
		allowCredentials,
		maxAge,
	)
}

func parseAllowedOrigins() []string {
	originsEnv := os.Getenv("CORS_ALLOWED_ORIGINS")
	if originsEnv == "" {
		return []string{}
	}

	origins := strings.Split(originsEnv, ",")
	trimmedOrigins := make([]string, len(origins))
	for i, origin := range origins {
		trimmedOrigins[i] = strings.TrimSpace(origin)
	}

	return trimmedOrigins
}

func parseAllowedMethods() []string {
	methodsEnv := os.Getenv("CORS_ALLOWED_METHODS")
	if methodsEnv == "" {
		return []string{}
	}

	methods := strings.Split(methodsEnv, ",")
	trimmedMethods := make([]string, len(methods))
	for i, method := range methods {
		trimmedMethods[i] = strings.TrimSpace(method)
	}

	return trimmedMethods
}
