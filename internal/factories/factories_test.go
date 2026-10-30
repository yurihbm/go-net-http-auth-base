package factories_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go-net-http-auth-base/config"
	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/factories"
	"go-net-http-auth-base/internal/middlewares"
	"go-net-http-auth-base/internal/telemetry"

	"github.com/stretchr/testify/assert"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// newTestConfig builds a minimal config with all required fields set.
func newTestConfig() *config.Config {
	return &config.Config{
		JWTSecret: "test-secret-key",
	}
}

// newTestDependencies builds the shared dependency graph with a nil pool.
// Passing nil is safe as long as we don't invoke methods that use the DB.
// The composition root itself only constructs the objects.
func newTestDependencies(t *testing.T) *factories.Dependencies {
	t.Helper()
	deps, err := factories.NewDependencies(nil, newTestConfig())
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
	controller := factories.AuthFactory(newTestDependencies(t), newTestConfig())
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
		middleware := factories.CORSFactory(config.CORSConfig{
			AllowedOrigins: []string{},
			AllowedMethods: []string{},
		})
		assert.NotNil(t, middleware)
		assert.IsType(t, &middlewares.CORSMiddleware{}, middleware)
	})

	t.Run("with configured values", func(t *testing.T) {
		origin := "http://example.com"

		middleware := factories.CORSFactory(config.CORSConfig{
			AllowedOrigins: []string{origin},
			AllowedMethods: []string{"GET", "POST"},
		})
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
	middleware := factories.RateLimitFactory(config.RateLimitConfig{
		RequestsPerSecond: 20.0,
		Burst:             50,
	})

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

func TestTelemetryFactory(t *testing.T) {
	newTelemetry := func(enabled bool) (*telemetry.Telemetry, *tracetest.SpanRecorder) {
		recorder := tracetest.NewSpanRecorder()
		return &telemetry.Telemetry{
			Enabled:        enabled,
			TracerProvider: sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)),
			MeterProvider:  metricnoop.NewMeterProvider(),
		}, recorder
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	t.Run("disabled - returns pass-through", func(t *testing.T) {
		tel, recorder := newTelemetry(false)
		middleware := factories.TelemetryFactory(tel, "api.test")
		w := httptest.NewRecorder()

		middleware.Use(next).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Empty(t, recorder.Ended())
	})

	t.Run("enabled - wraps handler", func(t *testing.T) {
		tel, recorder := newTelemetry(true)
		middleware := factories.TelemetryFactory(tel, "api.test")
		w := httptest.NewRecorder()

		middleware.Use(next).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Len(t, recorder.Ended(), 1)
	})
}
