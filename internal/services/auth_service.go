package services

import (
	"errors"
	"os"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const JWT_SECRET_KEY = "JWT_SECRET"

type authService struct {
	usersRepo domain.UsersRepository
}

func NewAuthService(usersRepo domain.UsersRepository) domain.AuthService {
	return &authService{
		usersRepo: usersRepo,
	}
}

func (s *authService) CredentialsLogin(dto domain.CredentialsLoginDTO) (domain.AuthTokens, error) {
	user, err := s.usersRepo.FindByEmail(dto.Email)
	if err != nil || user == nil {
		return domain.AuthTokens{}, errors.New("auth.authenticate.user_not_found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(dto.Password)); err != nil {
		return domain.AuthTokens{}, errors.New("auth.authenticate.invalid_credentials")
	}

	accessToken, err := s.GenerateToken(domain.GenerateTokenDTO{
		Subject:  user.UUID,
		Audience: domain.TokenAudienceAccess,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	refreshToken, err := s.GenerateToken(domain.GenerateTokenDTO{
		Subject:  user.UUID,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	return domain.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *authService) VerifyToken(dto domain.VerifyTokenDTO) (string, error) {
	token, err := jwt.Parse(dto.Token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(os.Getenv(JWT_SECRET_KEY)), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	sub := claims["sub"].(string)
	aud := domain.TokenAudience(claims["aud"].(string))
	if ok && token.Valid && aud == dto.Audience {
		return sub, nil
	}

	return "", errors.New("invalid token")
}

func (s *authService) RefreshToken(dto domain.RefreshTokenDTO) (domain.AuthTokens, error) {
	userUUID, err := s.VerifyToken(domain.VerifyTokenDTO{
		Token:    dto.RefreshToken,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	newAccessToken, err := s.GenerateToken(domain.GenerateTokenDTO{
		Subject:  userUUID,
		Audience: domain.TokenAudienceAccess,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	newRefreshToken, err := s.GenerateToken(domain.GenerateTokenDTO{
		Subject:  userUUID,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	return domain.AuthTokens{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *authService) GenerateToken(dto domain.GenerateTokenDTO) (string, error) {
	claims := jwt.MapClaims{
		"sub": dto.Subject,
		"exp": getTokenExpiration(dto.Audience),
		"aud": dto.Audience,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv(JWT_SECRET_KEY)))

}

func getTokenExpiration(audience domain.TokenAudience) int64 {
	switch audience {
	case domain.TokenAudienceRefresh:
		return time.Now().Add(domain.TokenExpirationRefresh).Unix()
	case domain.TokenAudienceExchange:
		return time.Now().Add(domain.TokenExpirationExchange).Unix()
	case domain.TokenAudienceOAuthState:
		return time.Now().Add(domain.TokenExpirationOAuthState).Unix()
	default:
		return time.Now().Add(domain.TokenExpirationAccess).Unix()
	}
}
