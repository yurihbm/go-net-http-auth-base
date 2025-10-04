package services

import (
	"errors"
	"os"
	"go-net-http-auth-base/internal/domain"
	"time"

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

func (s *authService) Authenticate(dto domain.AuthDTO) (string, string, error) {
	user, err := s.usersRepo.FindByEmail(dto.Email)
	if err != nil {
		return "", "", err
	}
	if user == nil {
		return "", "", errors.New("auth.authenticate.user_not_found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(dto.Password)); err != nil {
		return "", "", errors.New("auth.authenticate.invalid_credentials")
	}

	accessToken, err := s.generateAccessToken(user.UUID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.generateRefreshToken(user.UUID)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *authService) VerifyToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(os.Getenv(JWT_SECRET_KEY)), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["sub"].(string), nil
	}

	return "", errors.New("invalid token")
}

func (s *authService) RefreshToken(refreshTokenString string) (string, string, error) {
	userUUID, err := s.VerifyToken(refreshTokenString)
	if err != nil {
		return "", "", err
	}

	accessToken, err := s.generateAccessToken(userUUID)
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err := s.generateRefreshToken(userUUID)
	if err != nil {
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}

func (s *authService) generateAccessToken(userUUID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userUUID,
		"exp": time.Now().Add(time.Hour * 1).Unix(), // 1 hour
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv(JWT_SECRET_KEY)))
}

func (s *authService) generateRefreshToken(userUUID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userUUID,
		"exp": time.Now().Add(time.Hour * 24 * 7).Unix(), // 7 days
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv(JWT_SECRET_KEY)))
}
