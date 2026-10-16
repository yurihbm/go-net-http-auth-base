package services

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/golang-jwt/jwt/v5"
)

type tokenService struct {
	jwtSecret string
}

func NewTokenService(jwtSecret string) domain.TokenService {
	return &tokenService{jwtSecret: jwtSecret}
}

func (s *tokenService) VerifyToken(ctx context.Context, dto domain.VerifyTokenDTO) (*domain.VerifiedTokenData, error) {
	token, err := jwt.Parse(dto.Token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, domain.NewUnauthorizedError("auth.verifyToken.invalidTokenSigningMethod")
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	sub, subOk := claims["sub"].(string)
	audClaim, audOk := claims["aud"].(string)
	exp, expOk := claims["exp"].(float64)
	role, _ := claims["role"].(string)
	jti, _ := claims["jti"].(string)
	authTime, _ := claims["auth_time"].(float64)
	aud := domain.TokenAudience(audClaim)
	if !subOk || !audOk || !expOk || aud != dto.Audience {
		return nil, ErrInvalidToken
	}

	return &domain.VerifiedTokenData{
		Subject:    sub,
		Audience:   aud,
		Expiration: int64(exp),
		ID:         jti,
		AuthTime:   int64(authTime),
		Role:       domain.UserRole(role),
		Payload:    claims["payload"],
	}, nil
}

func (s *tokenService) GenerateToken(ctx context.Context, dto domain.GenerateTokenDTO) (string, error) {
	claims := jwt.MapClaims{
		"sub":     dto.Subject,
		"exp":     getTokenExpiration(dto.Audience),
		"aud":     dto.Audience,
		"payload": dto.Payload,
	}
	if dto.Role != "" {
		claims["role"] = dto.Role
	}
	if dto.ID != "" {
		claims["jti"] = dto.ID
	}
	if dto.AuthTime != 0 {
		claims["auth_time"] = dto.AuthTime
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := token.SignedString([]byte(s.jwtSecret))

	if err != nil {
		// Inner service usage of GenerateToken checks this error and return this
		// domain error with more contextual messages.
		// This domain error is returned to avoid leaking internal error details to
		// external calls.
		return "", domain.NewInternalServerError("auth.tokenGenerationFailed", err)
	}

	return signedString, nil
}

func getTokenExpiration(audience domain.TokenAudience) int64 {
	switch audience {
	case domain.TokenAudienceRefresh:
		return time.Now().Add(domain.TokenExpirationRefresh).Unix()
	case domain.TokenAudienceExchange:
		return time.Now().Add(domain.TokenExpirationExchange).Unix()
	case domain.TokenAudienceOAuthState:
		return time.Now().Add(domain.TokenExpirationOAuthState).Unix()
	case domain.TokenAudienceEmailVerification:
		return time.Now().Add(domain.TokenExpirationEmailVerification).Unix()
	default:
		return time.Now().Add(domain.TokenExpirationAccess).Unix()
	}
}
