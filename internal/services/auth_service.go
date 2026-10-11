package services

import (
	"context"
	"errors"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidToken = domain.NewUnauthorizedError("auth.invalidToken")

type authService struct {
	usersService          domain.UsersService
	authRepository        domain.AuthRepository
	oauthProviderRegistry domain.OAuthProviderRegistry
	transactor            domain.Transactor
	jwtSecret             string
}

func NewAuthService(
	usersService domain.UsersService,
	authRepository domain.AuthRepository,
	oauthProviderRegistry domain.OAuthProviderRegistry,
	transactor domain.Transactor,
	jwtSecret string,
) domain.AuthService {
	return &authService{
		usersService,
		authRepository,
		oauthProviderRegistry,
		transactor,
		jwtSecret,
	}
}

func (s *authService) CredentialsLogin(ctx context.Context, dto domain.CredentialsLoginDTO) (domain.AuthTokens, error) {
	user, err := s.usersService.GetByEmail(ctx, dto.Email)
	if err != nil || user == nil {
		var notFoundErr *domain.NotFoundError
		if err != nil && errors.As(err, &notFoundErr) {
			return domain.AuthTokens{}, domain.NewUnauthorizedError("auth.authenticate.invalidCredentials")
		}
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.authenticate.userFetchFailed", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(dto.Password)); err != nil {
		return domain.AuthTokens{}, domain.NewUnauthorizedError("auth.authenticate.invalidCredentials")
	}

	tokens, err := s.issueTokens(ctx, user.UUID)
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.authenticate.tokenGenerationFailed", err)
	}

	return tokens, nil
}

func (s *authService) VerifyToken(ctx context.Context, dto domain.VerifyTokenDTO) (*domain.VerifiedTokenData, error) {
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
	aud := domain.TokenAudience(audClaim)
	if !subOk || !audOk || !expOk || aud != dto.Audience {
		return nil, ErrInvalidToken
	}

	return &domain.VerifiedTokenData{
		Subject:    sub,
		Audience:   aud,
		Expiration: int64(exp),
		Payload:    claims["payload"],
	}, nil
}

func (s *authService) RefreshToken(ctx context.Context, dto domain.RefreshTokenDTO) (domain.AuthTokens, error) {
	tokenData, err := s.VerifyToken(ctx, domain.VerifyTokenDTO{
		Token:    dto.RefreshToken,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}
	userUUID := tokenData.Subject

	tokens, err := s.issueTokens(ctx, userUUID)
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.refreshToken.tokenGenerationFailed", err)
	}

	return tokens, nil
}

func (s *authService) issueTokens(ctx context.Context, userUUID string) (domain.AuthTokens, error) {
	accessToken, err := s.GenerateToken(ctx, domain.GenerateTokenDTO{
		Subject:  userUUID,
		Audience: domain.TokenAudienceAccess,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	refreshToken, err := s.GenerateToken(ctx, domain.GenerateTokenDTO{
		Subject:  userUUID,
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

func (s *authService) GenerateToken(ctx context.Context, dto domain.GenerateTokenDTO) (string, error) {
	claims := jwt.MapClaims{
		"sub":     dto.Subject,
		"exp":     getTokenExpiration(dto.Audience),
		"aud":     dto.Audience,
		"payload": dto.Payload,
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

func (s *authService) AddUserOAuthProvider(ctx context.Context, dto domain.AddUserOAuthProviderDTO) (*domain.UserOAuthProvider, error) {
	provider := domain.UserOAuthProvider{
		UserUUID:       dto.UserUUID,
		Provider:       dto.Provider,
		ProviderUserID: dto.ProviderUserID,
		ProviderEmail:  dto.ProviderEmail,
	}

	return s.authRepository.CreateUserOAuthProvider(ctx, provider)
}

func (s *authService) GetUserOAuthProvider(ctx context.Context, dto domain.GetUserOAuthProviderDTO) (*domain.UserOAuthProvider, error) {
	return s.authRepository.GetUserOAuthProviderByProviderAndProviderUserID(ctx, dto.Provider, dto.ProviderUserID)
}

func (s *authService) RemoveUserOAuthProvider(ctx context.Context, dto domain.RemoveUserOAuthProviderDTO) error {
	return s.authRepository.DeleteUserOAuthProvider(ctx, dto.ProviderUUID)
}

func (s *authService) GetUserOAuthProvidersByUserUUID(ctx context.Context, userUUID string) ([]domain.UserOAuthProvider, error) {
	return s.authRepository.ListUserOAuthProvidersByUserUUID(ctx, userUUID)
}

func (s *authService) GetOAuthProviderAuthURL(ctx context.Context, providerName domain.OAuthProviderName, state string) (string, error) {
	provider, err := s.oauthProviderRegistry.Get(providerName)
	if err != nil {
		return "", domain.NewValidationError("auth.oauthProvider.invalid", map[string]string{
			"provider": err.Error(),
		})
	}

	return provider.GetAuthURL(ctx, state), nil
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
		return nil, domain.NewInternalServerError("auth.oauthProvider.userInfoFetchFailed", err)
	}

	return userInfo, nil
}

func (s *authService) OAuthLogin(ctx context.Context, dto domain.OAuthLoginDTO) (*domain.OAuthLoginResult, error) {
	tokenData, err := s.VerifyToken(ctx, domain.VerifyTokenDTO{
		Token:    dto.State,
		Audience: domain.TokenAudienceOAuthState,
	})
	if err != nil {
		return nil, err
	}

	if tokenData.Subject != string(dto.Provider) {
		return nil, domain.NewUnauthorizedError("auth.oauthLogin.providerMismatch")
	}

	payload, _ := tokenData.Payload.(map[string]any)
	redirectURI, ok := payload["redirect_uri"].(string)
	if !ok {
		return nil, domain.NewValidationError(
			"auth.providerCallback.invalidStatePayload",
			map[string]string{
				"redirect_uri": "invalid redirect_uri in state payload",
			},
		)
	}

	userInfo, err := s.GetOAuthProviderUserInfo(ctx, dto.Provider, dto.Code)
	if err != nil {
		return nil, err
	}

	if userInfo.ID == "" || userInfo.Email == "" {
		details := map[string]string{}
		if userInfo.ID == "" {
			details["id"] = "user ID is required"
		}
		if userInfo.Email == "" {
			details["email"] = "user email is required"
		}
		return nil, domain.NewValidationError("auth.providerCallback.invalidUserInfo", details)
	}

	authenticatedUser, err := s.resolveOAuthUser(ctx, dto.Provider, userInfo)
	if err != nil {
		return nil, err
	}

	tokens, err := s.issueTokens(ctx, authenticatedUser.UUID)
	if err != nil {
		return nil, domain.NewInternalServerError("auth.oauthLogin.tokenGenerationFailed", err)
	}

	return &domain.OAuthLoginResult{
		User:        authenticatedUser,
		Tokens:      tokens,
		RedirectURI: redirectURI,
	}, nil
}

func (s *authService) resolveOAuthUser(ctx context.Context, provider domain.OAuthProviderName, userInfo *domain.OAuthProviderUserInfo) (*domain.User, error) {
	var notFoundErr *domain.NotFoundError

	userOAuthProvider, err := s.GetUserOAuthProvider(ctx, domain.GetUserOAuthProviderDTO{
		Provider:       provider,
		ProviderUserID: userInfo.ID,
	})
	if err != nil && !errors.As(err, &notFoundErr) {
		return nil, err
	}

	// Case 1: provider is already linked to a user.
	if userOAuthProvider != nil {
		return s.usersService.GetByUUID(ctx, userOAuthProvider.UserUUID)
	}

	existingUser, err := s.usersService.GetByEmail(ctx, userInfo.Email)
	if err != nil && !errors.As(err, &notFoundErr) {
		return nil, err
	}

	// Case 2: provider email matches an existing user account (link provider).
	// Require the provider to have verified this email to prevent account takeover.
	if existingUser != nil {
		if !userInfo.EmailVerified {
			return nil, domain.NewValidationError(
				"auth.providerCallback.emailNotVerified",
				map[string]string{
					"email": "provider email is not verified",
				},
			)
		}

		if _, err := s.AddUserOAuthProvider(ctx, domain.AddUserOAuthProviderDTO{
			UserUUID:       existingUser.UUID,
			Provider:       provider,
			ProviderUserID: userInfo.ID,
			ProviderEmail:  userInfo.Email,
		}); err != nil {
			return nil, err
		}

		return existingUser, nil
	}

	// Case 3: provider is not used and there is no user with this email (create user and link).
	var newUser *domain.User
	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		newUser, err = s.usersService.CreateOAuth(ctx, domain.CreateOAuthUserDTO{
			Name:  userInfo.Name,
			Email: userInfo.Email,
		})
		if err != nil {
			return err
		}

		_, err = s.AddUserOAuthProvider(ctx, domain.AddUserOAuthProviderDTO{
			UserUUID:       newUser.UUID,
			Provider:       provider,
			ProviderUserID: userInfo.ID,
			ProviderEmail:  userInfo.Email,
		})
		return err
	})
	if err != nil {
		return nil, err
	}

	return newUser, nil
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
