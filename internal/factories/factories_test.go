package factories_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	controller := factories.AuthFactory(newTestDependencies(t), newTestConfig(), passthroughMiddleware{})
	assert.NotNil(t, controller)
	assert.IsType(t, &controllers.AuthController{}, controller)
}

func TestUsersFactory(t *testing.T) {
	controller := factories.UsersFactory(newTestDependencies(t), newTestConfig(), passthroughMiddleware{})
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

func TestDocsFactory(t *testing.T) {
	controller := factories.DocsFactory(newTestDependencies(t))
	assert.NotNil(t, controller)
	assert.IsType(t, &controllers.DocsController{}, controller)
}

func TestLoggerFactory(t *testing.T) {
	middleware := factories.LoggerFactory()
	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.LoggerMiddleware{}, middleware)
}

func TestClientIPFactory(t *testing.T) {
	middleware := factories.ClientIPFactory([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.ClientIPMiddleware{}, middleware)
}

func TestCORSFactory(t *testing.T) {
	t.Run("success - default values", func(t *testing.T) {
		middleware := factories.CORSFactory(config.CORSConfig{
			AllowedOrigins: []string{},
			AllowedMethods: []string{},
		})
		assert.NotNil(t, middleware)
		assert.IsType(t, &middlewares.CORSMiddleware{}, middleware)
	})

	t.Run("success - with configured values", func(t *testing.T) {
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
		assert.Equal(t, "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After", w.Header().Get("Access-Control-Expose-Headers"))
	})
}

func TestRateLimitFactory(t *testing.T) {
	middleware := factories.RateLimitFactory(t.Context(), config.RateLimitConfig{
		RequestsPerSecond: 20.0,
		Burst:             50,
	})

	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.RateLimitMiddleware{}, middleware)
}

func TestCredentialsRateLimitFactory(t *testing.T) {
	middleware := factories.CredentialsRateLimitFactory(t.Context(), config.RateLimitConfig{
		CredentialsPerMinute: 5,
		CredentialsBurst:     10,
	})

	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.CredentialsRateLimitMiddleware{}, middleware)
}

func TestSecurityHeadersFactory(t *testing.T) {
	serve := func(env string) *httptest.ResponseRecorder {
		cfg := newTestConfig()
		cfg.Env = env
		w := httptest.NewRecorder()
		factories.SecurityHeadersFactory(cfg).Use(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
			ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		return w
	}

	t.Run("success - development has no HSTS", func(t *testing.T) {
		assert.Empty(t, serve("development").Header().Get("Strict-Transport-Security"))
	})

	t.Run("success - production sets HSTS", func(t *testing.T) {
		assert.NotEmpty(t, serve("production").Header().Get("Strict-Transport-Security"))
	})
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

	t.Run("success - disabled returns pass-through", func(t *testing.T) {
		tel, recorder := newTelemetry(false)
		middleware := factories.TelemetryFactory(tel, "api.test")
		w := httptest.NewRecorder()

		middleware.Use(next).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Empty(t, recorder.Ended())
	})

	t.Run("success - enabled wraps handler", func(t *testing.T) {
		tel, recorder := newTelemetry(true)
		middleware := factories.TelemetryFactory(tel, "api.test")
		w := httptest.NewRecorder()

		middleware.Use(next).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Len(t, recorder.Ended(), 1)
	})
}

func TestNewHandler(t *testing.T) {
	cfg := newTestConfig()
	cfg.RateLimit = config.RateLimitConfig{RequestsPerSecond: 100, Burst: 100, CredentialsPerMinute: 60, CredentialsBurst: 100}
	tel, err := telemetry.New(context.Background(), config.TelemetryConfig{}, "test")
	assert.NoError(t, err)
	handler := factories.NewHandler(t.Context(), newTestDependencies(t), cfg, tel)

	t.Run("success - GET /health returns 200", func(t *testing.T) {
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("error - GET /users/me without cookie returns 401", func(t *testing.T) {
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users/me", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
	newHandler := func(t *testing.T, rl config.RateLimitConfig) http.Handler {
		cfg := newTestConfig()
		cfg.RateLimit = rl
		return factories.NewHandler(t.Context(), newTestDependencies(t), cfg, tel)
	}
	serve := func(handler http.Handler, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	t.Run("success - security headers are set on regular responses", func(t *testing.T) {
		handler := newHandler(t, config.RateLimitConfig{RequestsPerSecond: 100, Burst: 100, CredentialsPerMinute: 60, CredentialsBurst: 10})

		w := serve(handler, http.MethodGet, "/health")

		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})

	t.Run("error - security headers are set on global rate limit 429", func(t *testing.T) {
		handler := newHandler(t, config.RateLimitConfig{RequestsPerSecond: 0.001, Burst: 1, CredentialsPerMinute: 60, CredentialsBurst: 10})
		serve(handler, http.MethodGet, "/health")

		w := serve(handler, http.MethodGet, "/health")

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", w.Header().Get("Content-Security-Policy"))
	})

	t.Run("error - credential limiter returns 429 on login after the burst and leaves other routes alone", func(t *testing.T) {
		handler := newHandler(t, config.RateLimitConfig{RequestsPerSecond: 100, Burst: 100, CredentialsPerMinute: 0.001, CredentialsBurst: 2})

		assert.Equal(t, http.StatusBadRequest, serve(handler, http.MethodPost, "/auth/login").Code)
		assert.Equal(t, http.StatusBadRequest, serve(handler, http.MethodPost, "/auth/login").Code)
		w := serve(handler, http.MethodPost, "/auth/login")

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "rateLimit.exceeded")
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, http.StatusOK, serve(handler, http.MethodGet, "/health").Code)
		assert.Equal(t, http.StatusUnauthorized, serve(handler, http.MethodGet, "/users/me").Code)
	})

}

type passthroughMiddleware struct{}

func (passthroughMiddleware) Use(next http.HandlerFunc) http.HandlerFunc { return next }

func TestRecoverFactory(t *testing.T) {
	middleware := factories.RecoverFactory()
	assert.NotNil(t, middleware)
	assert.IsType(t, &middlewares.RecoverMiddleware{}, middleware)
}
