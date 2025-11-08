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
	usersService   domain.UsersService
	authRepository domain.AuthRepository
}

func NewAuthService(usersService domain.UsersService, authRepository domain.AuthRepository) domain.AuthService {
	return &authService{
		usersService:   usersService,
		authRepository: authRepository,
	}
}

func (s *authService) CredentialsLogin(dto domain.CredentialsLoginDTO) (domain.AuthTokens, error) {
	user, err := s.usersService.GetByEmail(dto.Email)
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

func (s *authService) VerifyToken(dto domain.VerifyTokenDTO) (*domain.VerifiedTokenData, error) {
	token, err := jwt.Parse(dto.Token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(os.Getenv(JWT_SECRET_KEY)), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	sub := claims["sub"].(string)
	aud := domain.TokenAudience(claims["aud"].(string))
	exp := int64(claims["exp"].(float64))
	payload := claims["payload"]
	if ok && token.Valid && aud == dto.Audience {
		return &domain.VerifiedTokenData{
			Subject:    sub,
			Audience:   aud,
			Expiration: exp,
			Payload:    payload,
		}, nil
	}

	return nil, errors.New("invalid token")
}

func (s *authService) RefreshToken(dto domain.RefreshTokenDTO) (domain.AuthTokens, error) {
	tokenData, err := s.VerifyToken(domain.VerifyTokenDTO{
		Token:    dto.RefreshToken,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}
	userUUID := tokenData.Subject

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
		"sub":     dto.Subject,
		"exp":     getTokenExpiration(dto.Audience),
		"aud":     dto.Audience,
		"payload": dto.Payload,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv(JWT_SECRET_KEY)))

}

func (s *authService) AddUserOAuthProvider(dto domain.AddUserOAuthProviderDTO) (*domain.UserOAuthProvider, error) {
	provider := domain.UserOAuthProvider{
		UserUUID:       dto.UserUUID,
		Provider:       dto.Provider,
		ProviderUserID: dto.ProviderUserID,
		ProviderEmail:  dto.ProviderEmail,
	}

	return s.authRepository.CreateUserOAuthProvider(provider)
}

func (s *authService) GetUserOAuthProvider(dto domain.GetUserOAuthProviderDTO) (*domain.UserOAuthProvider, error) {
	return s.authRepository.GetUserOAuthProviderByProviderAndProviderUserID(dto.Provider, dto.ProviderUserID)
}

func (s *authService) RemoveUserOAuthProvider(dto domain.RemoveUserOAuthProviderDTO) error {
	return s.authRepository.DeleteUserOAuthProvider(dto.ProviderUUID)
}

func (s *authService) GetUserOAuthProvidersByUserUUID(userUUID string) ([]domain.UserOAuthProvider, error) {
	return s.authRepository.ListUserOAuthProvidersByUserUUID(userUUID)
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
