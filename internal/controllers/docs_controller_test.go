package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-net-http-auth-base/internal/controllers"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type rejectingMiddleware struct {
	status int
}

func (m rejectingMiddleware) Use(_ http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(m.status)
	}
}

func TestDocsController_RegisterRoutes(t *testing.T) {
	t.Run("success - serves the spec when the middlewares pass", func(t *testing.T) {
		router := http.NewServeMux()
		authMiddleware := new(mocks.AuthMiddlewareMock)
		roleMiddleware := new(mocks.AuthMiddlewareMock)
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		roleMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		controllers.NewDocsController(authMiddleware, roleMiddleware).RegisterRoutes(router)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/doc.json", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
		assert.Contains(t, w.Body.String(), `"swagger"`)
		authMiddleware.AssertNumberOfCalls(t, "Use", 1)
		roleMiddleware.AssertNumberOfCalls(t, "Use", 1)
	})

	t.Run("success - serves the UI when the middlewares pass", func(t *testing.T) {
		router := http.NewServeMux()
		authMiddleware := new(mocks.AuthMiddlewareMock)
		roleMiddleware := new(mocks.AuthMiddlewareMock)
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		roleMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		controllers.NewDocsController(authMiddleware, roleMiddleware).RegisterRoutes(router)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "swagger-ui")
	})

	t.Run("success - UI injects the logout button and the logout interceptor", func(t *testing.T) {
		router := http.NewServeMux()
		authMiddleware := new(mocks.AuthMiddlewareMock)
		roleMiddleware := new(mocks.AuthMiddlewareMock)
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		roleMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		controllers.NewDocsController(authMiddleware, roleMiddleware).RegisterRoutes(router)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "swagger-ui-logout-button")
		assert.Contains(t, w.Body.String(), "/auth/logout")
		assert.Contains(t, w.Body.String(), "responseInterceptor")
	})

	t.Run("success - logout script is not parsed as a call on window.ui", func(t *testing.T) {
		router := http.NewServeMux()
		authMiddleware := new(mocks.AuthMiddlewareMock)
		roleMiddleware := new(mocks.AuthMiddlewareMock)
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		roleMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		controllers.NewDocsController(authMiddleware, roleMiddleware).RegisterRoutes(router)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil))

		_, afterUI, found := strings.Cut(w.Body.String(), "window.ui = ui")
		assert.True(t, found)
		assert.True(t, strings.HasPrefix(strings.TrimSpace(afterUI), ";"))
	})

	t.Run("error - rejected when the auth middleware rejects", func(t *testing.T) {
		router := http.NewServeMux()
		roleMiddleware := new(mocks.AuthMiddlewareMock)
		roleMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		controllers.NewDocsController(rejectingMiddleware{http.StatusUnauthorized}, roleMiddleware).RegisterRoutes(router)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/doc.json", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.NotContains(t, w.Body.String(), `"swagger"`)
	})

	t.Run("error - rejected when the role middleware rejects", func(t *testing.T) {
		router := http.NewServeMux()
		authMiddleware := new(mocks.AuthMiddlewareMock)
		authMiddleware.On("Use", mock.Anything).Return(mock.Anything)
		controllers.NewDocsController(authMiddleware, rejectingMiddleware{http.StatusForbidden}).RegisterRoutes(router)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/doc.json", nil))

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.NotContains(t, w.Body.String(), `"swagger"`)
	})

	t.Run("success - serves the public login gate without the middlewares", func(t *testing.T) {
		router := http.NewServeMux()
		controllers.NewDocsController(rejectingMiddleware{http.StatusUnauthorized}, rejectingMiddleware{http.StatusForbidden}).RegisterRoutes(router)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/", nil))

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
		assert.Equal(t, "frame-ancestors 'none'", w.Header().Get("Content-Security-Policy"))
		assert.Contains(t, w.Body.String(), "/auth/login")
	})

	t.Run("error - index.html stays behind the middlewares", func(t *testing.T) {
		router := http.NewServeMux()
		controllers.NewDocsController(rejectingMiddleware{http.StatusUnauthorized}, rejectingMiddleware{http.StatusForbidden}).RegisterRoutes(router)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
