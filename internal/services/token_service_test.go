package services_test

import (
	"context"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/services"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tokenSecret = "test-secret-key"

func TestTokenService_RoundTrip(t *testing.T) {
	service := services.NewTokenService(tokenSecret)

	token, err := service.GenerateToken(context.Background(), domain.GenerateTokenDTO{
		Subject:  "user-uuid",
		Audience: domain.TokenAudienceAccess,
		Role:     domain.RoleAdmin,
		Payload:  map[string]string{"key": "value"},
	})
	require.NoError(t, err)

	data, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
		Token:    token,
		Audience: domain.TokenAudienceAccess,
	})

	require.NoError(t, err)
	assert.Equal(t, "user-uuid", data.Subject)
	assert.Equal(t, domain.TokenAudienceAccess, data.Audience)
	assert.Equal(t, domain.RoleAdmin, data.Role)
	assert.Equal(t, map[string]any{"key": "value"}, data.Payload)
	assert.InDelta(t, time.Now().Add(domain.TokenExpirationAccess).Unix(), data.Expiration, 5)
}

func TestTokenService_Expiration(t *testing.T) {
	service := services.NewTokenService(tokenSecret)
	cases := map[domain.TokenAudience]time.Duration{
		domain.TokenAudienceAccess:            domain.TokenExpirationAccess,
		domain.TokenAudienceRefresh:           domain.TokenExpirationRefresh,
		domain.TokenAudienceExchange:          domain.TokenExpirationExchange,
		domain.TokenAudienceOAuthState:        domain.TokenExpirationOAuthState,
		domain.TokenAudienceEmailVerification: domain.TokenExpirationEmailVerification,
	}

	for audience, ttl := range cases {
		t.Run(string(audience), func(t *testing.T) {
			token, err := service.GenerateToken(context.Background(), domain.GenerateTokenDTO{
				Subject:  "user-uuid",
				Audience: audience,
			})
			require.NoError(t, err)

			data, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
				Token:    token,
				Audience: audience,
			})

			require.NoError(t, err)
			assert.InDelta(t, time.Now().Add(ttl).Unix(), data.Expiration, 5)
		})
	}
}

func TestTokenService_VerifyToken_Rejects(t *testing.T) {
	service := services.NewTokenService(tokenSecret)
	sign := func(t *testing.T, claims jwt.MapClaims, secret string) string {
		t.Helper()
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		require.NoError(t, err)
		return token
	}

	cases := map[string]string{
		"expired": sign(t, jwt.MapClaims{
			"sub": "user-uuid",
			"aud": domain.TokenAudienceAccess,
			"exp": time.Now().Add(-time.Minute).Unix(),
		}, tokenSecret),
		"wrong audience": sign(t, jwt.MapClaims{
			"sub": "user-uuid",
			"aud": domain.TokenAudienceRefresh,
			"exp": time.Now().Add(time.Minute).Unix(),
		}, tokenSecret),
		"bad signature": sign(t, jwt.MapClaims{
			"sub": "user-uuid",
			"aud": domain.TokenAudienceAccess,
			"exp": time.Now().Add(time.Minute).Unix(),
		}, "different-secret-key"),
		"garbage": "not-a-token",
	}

	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
				Token:    token,
				Audience: domain.TokenAudienceAccess,
			})

			assert.Equal(t, services.ErrInvalidToken, err)
			assert.Nil(t, data)
		})
	}
}

func TestTokenService_RoundTrip_SessionClaims(t *testing.T) {
	service := services.NewTokenService(tokenSecret)
	authTime := time.Now().Add(-time.Hour).Unix()

	token, err := service.GenerateToken(context.Background(), domain.GenerateTokenDTO{
		Subject:  "user-uuid",
		Audience: domain.TokenAudienceRefresh,
		ID:       "refresh-jti",
		AuthTime: authTime,
	})
	require.NoError(t, err)

	data, err := service.VerifyToken(context.Background(), domain.VerifyTokenDTO{
		Token:    token,
		Audience: domain.TokenAudienceRefresh,
	})

	require.NoError(t, err)
	assert.Equal(t, "refresh-jti", data.ID)
	assert.Equal(t, authTime, data.AuthTime)
}
