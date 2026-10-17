package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"strings"

	"go-net-http-auth-base/internal/domain"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidToken             = domain.NewUnauthorizedError("auth.invalidToken")
	ErrOAuthNonceMismatch       = domain.NewUnauthorizedError("auth.oauthLogin.nonceMismatch")
	ErrOAuthMissingCodeVerifier = domain.NewUnauthorizedError("auth.oauthLogin.missingCodeVerifier")
)

type authService struct {
	usersService          domain.UsersService
	authRepository        domain.AuthRepository
	oauthProviderRegistry domain.OAuthProviderRegistry
	transactor            domain.Transactor
	tokens                domain.TokenService
}

func NewAuthService(
	usersService domain.UsersService,
	authRepository domain.AuthRepository,
	oauthProviderRegistry domain.OAuthProviderRegistry,
	transactor domain.Transactor,
	tokens domain.TokenService,
) domain.AuthService {
	return &authService{
		usersService,
		authRepository,
		oauthProviderRegistry,
		transactor,
		tokens,
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

	tokens, err := s.issueTokens(ctx, user.UUID, user.Role)
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.authenticate.tokenGenerationFailed", err)
	}

	return tokens, nil
}

func (s *authService) VerifyToken(ctx context.Context, dto domain.VerifyTokenDTO) (*domain.VerifiedTokenData, error) {
	return s.tokens.VerifyToken(ctx, dto)
}

func (s *authService) RefreshToken(ctx context.Context, dto domain.RefreshTokenDTO) (domain.AuthTokens, error) {
	tokenData, err := s.VerifyToken(ctx, domain.VerifyTokenDTO{
		Token:    dto.RefreshToken,
		Audience: domain.TokenAudienceRefresh,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	user, err := s.usersService.GetByUUID(ctx, domain.Actor{UUID: tokenData.Subject}, tokenData.Subject)
	if err != nil {
		return domain.AuthTokens{}, err
	}

	tokens, err := s.issueTokens(ctx, user.UUID, user.Role)
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.refreshToken.tokenGenerationFailed", err)
	}

	return tokens, nil
}

func (s *authService) issueTokens(ctx context.Context, userUUID string, role domain.UserRole) (domain.AuthTokens, error) {
	accessToken, err := s.GenerateToken(ctx, domain.GenerateTokenDTO{
		Subject:  userUUID,
		Audience: domain.TokenAudienceAccess,
		Role:     role,
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
	return s.tokens.GenerateToken(ctx, dto)
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

func (s *authService) StartOAuthLogin(ctx context.Context, dto domain.StartOAuthLoginDTO) (*domain.StartOAuthLoginResult, error) {
	provider, err := s.getOAuthProvider(dto.Provider)
	if err != nil {
		return nil, err
	}

	nonce := rand.Text()
	codeVerifier := oauth2.GenerateVerifier()

	state, err := s.GenerateToken(ctx, domain.GenerateTokenDTO{
		Audience: domain.TokenAudienceOAuthState,
		Subject:  string(dto.Provider),
		Payload: map[string]string{
			"redirect_uri": dto.RedirectURI,
			"nonce":        nonce,
		},
	})
	if err != nil {
		return nil, err
	}

	return &domain.StartOAuthLoginResult{
		AuthURL:      provider.GetAuthURL(ctx, state, codeVerifier),
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
	}, nil
}

func (s *authService) GetOAuthProviderUserInfo(ctx context.Context, providerName domain.OAuthProviderName, code string, codeVerifier string) (*domain.OAuthProviderUserInfo, error) {
	provider, err := s.getOAuthProvider(providerName)
	if err != nil {
		return nil, err
	}

	userInfo, err := provider.GetUserInfo(ctx, code, codeVerifier)
	if err != nil {
		return nil, domain.NewInternalServerError("auth.oauthProvider.userInfoFetchFailed", err)
	}

	return userInfo, nil
}

func (s *authService) getOAuthProvider(name domain.OAuthProviderName) (domain.OAuthProvider, error) {
	provider, err := s.oauthProviderRegistry.Get(name)
	if err != nil {
		return nil, domain.NewValidationError("auth.oauthProvider.invalid", map[string]string{
			"provider": err.Error(),
		})
	}

	return provider, nil
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

	stateNonce, _ := payload["nonce"].(string)
	if dto.Nonce == "" || subtle.ConstantTimeCompare([]byte(stateNonce), []byte(dto.Nonce)) != 1 {
		return nil, ErrOAuthNonceMismatch
	}

	if dto.CodeVerifier == "" {
		return nil, ErrOAuthMissingCodeVerifier
	}

	providerUserInfo, err := s.GetOAuthProviderUserInfo(ctx, dto.Provider, dto.Code, dto.CodeVerifier)
	if err != nil {
		return nil, err
	}

	userInfo := *providerUserInfo
	userInfo.Email = strings.ToLower(strings.TrimSpace(userInfo.Email))

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

	authenticatedUser, err := s.resolveOAuthUser(ctx, dto.Provider, &userInfo)
	if err != nil {
		return nil, err
	}

	tokens, err := s.issueTokens(ctx, authenticatedUser.UUID, authenticatedUser.Role)
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
	user, err := s.resolveOAuthUserWithinTx(ctx, provider, userInfo)

	// A concurrent or replayed callback may have created the user or link first;
	// its transaction has committed, so resolving again finds the existing records.
	var conflictErr *domain.ConflictError
	if errors.As(err, &conflictErr) {
		return s.resolveOAuthUserWithinTx(ctx, provider, userInfo)
	}

	return user, err
}

func (s *authService) resolveOAuthUserWithinTx(ctx context.Context, provider domain.OAuthProviderName, userInfo *domain.OAuthProviderUserInfo) (*domain.User, error) {
	var user *domain.User
	err := s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		user, err = s.findOrCreateOAuthUser(ctx, provider, userInfo)
		return err
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *authService) findOrCreateOAuthUser(ctx context.Context, provider domain.OAuthProviderName, userInfo *domain.OAuthProviderUserInfo) (*domain.User, error) {
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
		return s.usersService.GetByUUID(ctx, domain.Actor{UUID: userOAuthProvider.UserUUID}, userOAuthProvider.UserUUID)
	}

	existingUser, err := s.usersService.GetByEmail(ctx, userInfo.Email)
	if err != nil && !errors.As(err, &notFoundErr) {
		return nil, err
	}

	// Both Case 2 and Case 3 trust the provider's claim of owning this email.
	if !userInfo.EmailVerified {
		return nil, domain.NewValidationError(
			"auth.providerCallback.emailNotVerified",
			map[string]string{
				"email": "provider email is not verified",
			},
		)
	}

	// Case 2: provider email matches an existing user account (link provider).
	// The local account must be verified too, otherwise whoever pre-registered
	// this email without owning it would share the account with the real owner.
	if existingUser != nil {
		if !existingUser.EmailVerified {
			return nil, domain.NewValidationError(
				"auth.providerCallback.localEmailNotVerified",
				map[string]string{
					"email": "local account email is not verified",
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
	newUser, err := s.usersService.CreateOAuth(ctx, domain.CreateOAuthUserDTO{
		Name:          userInfo.Name,
		Email:         userInfo.Email,
		EmailVerified: true,
	})
	if err != nil {
		return nil, err
	}

	if _, err := s.AddUserOAuthProvider(ctx, domain.AddUserOAuthProviderDTO{
		UserUUID:       newUser.UUID,
		Provider:       provider,
		ProviderUserID: userInfo.ID,
		ProviderEmail:  userInfo.Email,
	}); err != nil {
		return nil, err
	}

	return newUser, nil
}
