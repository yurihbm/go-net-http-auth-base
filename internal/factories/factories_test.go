package factories_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/factories"
	"go-net-http-auth-base/internal/middlewares"

	"github.com/stretchr/testify/assert"
)

// newTestDependencies builds the shared dependency graph with a nil pool.
// Passing nil is safe as long as we don't invoke methods that use the DB.
// The composition root itself only constructs the objects.
func newTestDependencies(t *testing.T) *factories.Dependencies {
	t.Helper()
	deps, err := factories.NewDependencies(nil)
	assert.NoError(t, err)
	assert.NotNil(t, deps)
	return deps
}

func TestNewDependencies(t *testing.T) {
	deps := newTestDependencies(t)

	assert.NotNil(t, deps.UsersService)
	assert.NotNil(t, deps.AuthService)
	assert.NotNil(t, deps.AuditService)
	assert.NotNil(t, deps.AuthMiddleware)
	assert.NotNil(t, deps.AdminRoleMiddleware)
}

func TestAuthFactory(t *testing.T) {
	controller := factories.AuthFactory(newTestDependencies(t))
	assert.NotNil(t, controller)
	assert.IsType(t, &controllers.AuthController{}, controller)
}

func TestUsersFactory(t *testing.T) {
	controller := factories.UsersFactory(newTestDependencies(t))
	assert.NotNil(t, controller)
	assert.IsType(t, &controllers.UsersController{}, controller)
}

func TestHealthFactory(t *testing.T) {
	controller := factories.HealthFactory(newTestDependencies(t))
	assert.NotNil(t, controller)
	assert.IsType(t, &controllers.HealthController{}, controller)
}

func TestAuditFactory(t *testing.T) {
	controller := factories.AuditFactory(newTestDependencies(t))
	assert.NotNil(t, controller)
	assert.IsType(t, &controllers.AuditController{}, controller)
}

func TestLoggerFactory(t *testing.T) {
	middleware := factories.LoggerFactory()
	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.LoggerMiddleware{}, middleware)
}

func TestCORSFactory(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		t.Setenv("CORS_ALLOWED_ORIGINS", "")
		t.Setenv("CORS_ALLOWED_METHODS", "")

		middleware := factories.CORSFactory()
		assert.NotNil(t, middleware)
		assert.IsType(t, &middlewares.CORSMiddleware{}, middleware)
	})

	t.Run("with env vars", func(t *testing.T) {
		origin := "http://example.com"
		t.Setenv("CORS_ALLOWED_ORIGINS", origin)
		t.Setenv("CORS_ALLOWED_METHODS", "GET,POST")

		middleware := factories.CORSFactory()
		assert.NotNil(t, middleware)

		// Verify behavior
		handler := middleware.Use(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, origin, w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "GET, POST", w.Header().Get("Access-Control-Allow-Methods"))
	})
}

func TestRateLimitFactory(t *testing.T) {
	middleware := factories.RateLimitFactory()

	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.RateLimitMiddleware{}, middleware)
}

func TestRequestContextDataFactory(t *testing.T) {
	middleware := factories.RequestContextDataFactory()

	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.RequestContextDataMiddleware{}, middleware)
}

func TestRequestUUIDFactory(t *testing.T) {
	middleware := factories.RequestUUIDFactory()

	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.RequestUUIDMiddleware{}, middleware)
}
