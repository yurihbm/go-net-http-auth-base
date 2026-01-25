package services

import (
	"context"
	"errors"
	"os"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const JWT_SECRET_KEY = "JWT_SECRET"

var ErrInvalidToken = domain.NewUnauthorizedError("auth.invalidToken")

type authService struct {
	usersService          domain.UsersService
	authRepository        domain.AuthRepository
	oauthProviderRegistry domain.OAuthProviderRegistry
}

func NewAuthService(
	usersService domain.UsersService,
	authRepository domain.AuthRepository,
	oauthProviderRegistry domain.OAuthProviderRegistry,
) domain.AuthService {
	return &authService{
		usersService,
		authRepository,
		oauthProviderRegistry,
	}
}

func (s *authService) CredentialsLogin(dto domain.CredentialsLoginDTO) (domain.AuthTokens, error) {
	user, err := s.usersService.GetByEmail(dto.Email)
	if err != nil || user == nil {
		var notFoundErr *domain.NotFoundError
		if err != nil && errors.As(err, &notFoundErr) {
			return domain.AuthTokens{}, domain.NewUnauthorizedError("auth.authenticate.invalidCredentials")
		}
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.authenticate.userFetchFailed")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(dto.Password)); err != nil {
		return domain.AuthTokens{}, domain.NewUnauthorizedError("auth.authenticate.invalidCredentials")
	}

	accessToken, err := s.GenerateToken(domain.GenerateTokenDTO{
		Subject:  user.UUID,
		Audience: domain.TokenAudienceAccess,
	})
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.authenticate.tokenGenerationFailed")
	}

	refreshToken, err := s.GenerateToken(domain.GenerateTokenDTO{
		Subject:  user.UUID,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.authenticate.tokenGenerationFailed")
	}

	return domain.AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *authService) VerifyToken(dto domain.VerifyTokenDTO) (*domain.VerifiedTokenData, error) {
	token, err := jwt.Parse(dto.Token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, domain.NewUnauthorizedError("auth.verifyToken.invalidTokenSigningMethod")
		}
		return []byte(os.Getenv(JWT_SECRET_KEY)), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
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

	return nil, ErrInvalidToken
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
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.refreshToken.tokenGenerationFailed")
	}

	newRefreshToken, err := s.GenerateToken(domain.GenerateTokenDTO{
		Subject:  userUUID,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.refreshToken.tokenGenerationFailed")
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
	signedString, err := token.SignedString([]byte(os.Getenv(JWT_SECRET_KEY)))

	if err != nil {
		// Inner service usage of GenerateToken checks this error and return this
		// domain error with more contextual messages.
		// This domain error is returned to avoid leaking internal error details to
		// external calls.
		return "", domain.NewInternalServerError("auth.tokenGenerationFailed")
	}

	return signedString, nil
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

func (s *authService) GetOAuthProviderAuthURL(providerName domain.OAuthProviderName, state string) (string, error) {
	provider, err := s.oauthProviderRegistry.Get(providerName)
	if err != nil {
		return "", domain.NewValidationError("auth.oauthProvider.invalid", map[string]string{
			"provider": err.Error(),
		})
	}

	return provider.GetAuthURL(state), nil
}

func (s *authService) GetOAuthProviderUserInfo(ctx context.Context, providerName domain.OAuthProviderName, code string) (*domain.OAuthProviderUserInfo, error) {
	provider, err := s.oauthProviderRegistry.Get(providerName)
	if err != nil {
		return nil, domain.NewValidationError("auth.oauthProvider.invalid", map[string]string{
			"provider": err.Error(),
		})
	}

	userInfo, err := provider.GetUserInfo(ctx, code)
	if err != nil {
		return nil, domain.NewInternalServerError("auth.oauthProvider.userInfoFetchFailed")
	}

	return userInfo, nil
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
