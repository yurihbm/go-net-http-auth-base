package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"log/slog"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidToken             = domain.NewUnauthorizedError("auth.invalidToken")
	ErrOAuthNonceMismatch       = domain.NewUnauthorizedError("auth.oauthLogin.nonceMismatch")
	ErrOAuthMissingCodeVerifier = domain.NewUnauthorizedError("auth.oauthLogin.missingCodeVerifier")

	errOAuthEmailUnverified = errors.New("oauth provider email is not verified")
	errOAuthLinkStaleToken  = domain.NewUnauthorizedError("auth.oauthLink.staleToken")
)

type authService struct {
	usersService          domain.UsersService
	pendingSignups        domain.PendingSignupService
	authRepository        domain.AuthRepository
	sessionsRepository    domain.SessionsRepository
	oauthProviderRegistry domain.OAuthProviderRegistry
	transactor            domain.Transactor
	tokens                domain.TokenService
	emailVerification     domain.EmailVerificationService
	sessionMaxAge         time.Duration
	maxSessionsPerUser    int
}

func NewAuthService(
	usersService domain.UsersService,
	pendingSignups domain.PendingSignupService,
	authRepository domain.AuthRepository,
	sessionsRepository domain.SessionsRepository,
	oauthProviderRegistry domain.OAuthProviderRegistry,
	transactor domain.Transactor,
	tokens domain.TokenService,
	emailVerification domain.EmailVerificationService,
	sessionMaxAge time.Duration,
	maxSessionsPerUser int,
) domain.AuthService {
	return &authService{
		usersService,
		pendingSignups,
		authRepository,
		sessionsRepository,
		oauthProviderRegistry,
		transactor,
		tokens,
		emailVerification,
		sessionMaxAge,
		maxSessionsPerUser,
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

	tokens, err := s.startSession(ctx, user)
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.authenticate.tokenGenerationFailed", err)
	}

	return tokens, nil
}

// The attempt is counted outside the transaction so a wrong code is never rolled
// back. If the account cannot be created or linked (email taken meanwhile), the
// rollback keeps the pending signup. An OAuth conflict may come from a concurrent
// link or create, so it runs once more in a fresh transaction, where Consume
// finds the restored pending signup and the records that won the race.
func (s *authService) CompleteSignup(ctx context.Context, pendingUUID string, code string) (*domain.SignupResult, error) {
	if err := s.pendingSignups.Attempt(ctx, pendingUUID, code); err != nil {
		return nil, err
	}

	result, kind, err := s.completeSignupWithinTx(ctx, pendingUUID, code)

	var conflictErr *domain.ConflictError
	if kind == domain.PendingSignupKindOAuth && errors.As(err, &conflictErr) {
		result, _, err = s.completeSignupWithinTx(ctx, pendingUUID, code)
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *authService) completeSignupWithinTx(ctx context.Context, pendingUUID string, code string) (*domain.SignupResult, domain.PendingSignupKind, error) {
	var result domain.SignupResult
	var kind domain.PendingSignupKind
	err := s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		pending, err := s.pendingSignups.Consume(ctx, pendingUUID, code)
		if err != nil {
			return err
		}
		kind = pending.Kind

		if pending.Kind == domain.PendingSignupKindOAuth {
			result.User, _, err = s.findOrCreateOAuthUser(ctx, pending.Provider, &domain.OAuthProviderUserInfo{
				ID:            pending.ProviderUserID,
				Name:          pending.Name,
				Email:         pending.Email,
				EmailVerified: true,
			})
		} else {
			result.User, err = s.usersService.Create(ctx, domain.NewUserDTO{
				Name:         pending.Name,
				Email:        pending.Email,
				PasswordHash: pending.PasswordHash,
			})
		}
		if err != nil {
			return err
		}

		result.Tokens, err = s.startSession(ctx, result.User)
		if err != nil {
			return domain.NewInternalServerError("auth.signup.tokenGenerationFailed", err)
		}
		return nil
	})
	if err != nil {
		return nil, kind, err
	}

	return &result, kind, nil
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

	if tokenData.ID == "" || tokenData.SessionID == "" {
		return domain.AuthTokens{}, ErrInvalidToken
	}

	userUUID, sessionUUID := tokenData.Subject, tokenData.SessionID
	var notFoundErr *domain.NotFoundError

	session, err := s.sessionsRepository.FindByUUID(ctx, userUUID, sessionUUID)
	if err != nil {
		if errors.As(err, &notFoundErr) {
			return domain.AuthTokens{}, ErrInvalidToken
		}
		return domain.AuthTokens{}, err
	}

	if time.Now().Unix() >= session.ExpiresAt || session.CurrentJTI != tokenData.ID {
		return domain.AuthTokens{}, s.revokeSession(ctx, userUUID, sessionUUID)
	}

	nextUUID, err := uuid.NewV7()
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.refreshToken.tokenGenerationFailed", err)
	}
	nextJTI := nextUUID.String()
	if err := s.sessionsRepository.RotateJTI(ctx, userUUID, sessionUUID, tokenData.ID, nextJTI); err != nil {
		if errors.As(err, &notFoundErr) {
			return domain.AuthTokens{}, s.revokeSession(ctx, userUUID, sessionUUID)
		}
		return domain.AuthTokens{}, err
	}

	user, err := s.usersService.GetByUUID(ctx, domain.Actor{UUID: userUUID}, userUUID)
	if err != nil {
		if errors.As(err, &notFoundErr) {
			return domain.AuthTokens{}, ErrInvalidToken
		}
		return domain.AuthTokens{}, err
	}

	tokens, err := s.issueTokens(ctx, user, sessionUUID, nextJTI)
	if err != nil {
		return domain.AuthTokens{}, domain.NewInternalServerError("auth.refreshToken.tokenGenerationFailed", err)
	}

	return tokens, nil
}

func (s *authService) revokeSession(ctx context.Context, userUUID string, sessionUUID string) error {
	if err := s.sessionsRepository.Delete(ctx, userUUID, sessionUUID); err != nil {
		return err
	}
	return ErrInvalidToken
}

func (s *authService) Logout(ctx context.Context, userUUID string, sessionUUID string) error {
	return s.sessionsRepository.Delete(ctx, userUUID, sessionUUID)
}

func (s *authService) LogoutOthers(ctx context.Context, userUUID string, sessionUUID string) error {
	session, err := s.sessionsRepository.FindByUUID(ctx, userUUID, sessionUUID)
	if err != nil {
		var notFoundErr *domain.NotFoundError
		if errors.As(err, &notFoundErr) {
			return ErrInvalidToken
		}
		return err
	}
	if time.Now().Unix() >= session.ExpiresAt {
		return ErrInvalidToken
	}

	return s.sessionsRepository.DeleteOthersByUser(ctx, userUUID, sessionUUID)
}

func (s *authService) startSession(ctx context.Context, user *domain.User) (domain.AuthTokens, error) {
	var tokens domain.AuthTokens
	err := s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		if err := s.sessionsRepository.DeleteExpiredByUser(ctx, user.UUID, domain.TokenExpirationRefresh); err != nil {
			return err
		}

		jtiUUID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		jti := jtiUUID.String()
		session, err := s.sessionsRepository.Create(ctx, domain.UserSession{
			UserUUID:   user.UUID,
			CurrentJTI: jti,
			ExpiresAt:  time.Now().Add(s.sessionMaxAge).Unix(),
		})
		if err != nil {
			return err
		}

		if err := s.sessionsRepository.DeleteOldestBeyond(ctx, user.UUID, s.maxSessionsPerUser); err != nil {
			return err
		}

		tokens, err = s.issueTokens(ctx, user, session.UUID, jti)
		return err
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	return tokens, nil
}

func (s *authService) issueTokens(ctx context.Context, user *domain.User, sessionUUID string, refreshJTI string) (domain.AuthTokens, error) {
	accessToken, err := s.GenerateToken(ctx, domain.GenerateTokenDTO{
		Subject:   user.UUID,
		Audience:  domain.TokenAudienceAccess,
		SessionID: sessionUUID,
		Role:      user.Role,
	})
	if err != nil {
		return domain.AuthTokens{}, err
	}

	refreshToken, err := s.GenerateToken(ctx, domain.GenerateTokenDTO{
		Subject:   user.UUID,
		Audience:  domain.TokenAudienceRefresh,
		SessionID: sessionUUID,
		ID:        refreshJTI,
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

func (s *authService) VerifyOAuthState(ctx context.Context, dto domain.VerifyOAuthStateDTO) (string, error) {
	tokenData, err := s.VerifyToken(ctx, domain.VerifyTokenDTO{
		Token:    dto.State,
		Audience: domain.TokenAudienceOAuthState,
	})
	if err != nil {
		return "", err
	}

	if tokenData.Subject != string(dto.Provider) {
		return "", domain.NewUnauthorizedError("auth.oauthLogin.providerMismatch")
	}

	payload, _ := tokenData.Payload.(map[string]any)
	redirectURI, ok := payload["redirect_uri"].(string)
	if !ok {
		return "", domain.NewValidationError(
			"auth.providerCallback.invalidStatePayload",
			map[string]string{
				"redirect_uri": "invalid redirect_uri in state payload",
			},
		)
	}

	stateNonce, _ := payload["nonce"].(string)
	if dto.Nonce == "" || subtle.ConstantTimeCompare([]byte(stateNonce), []byte(dto.Nonce)) != 1 {
		return "", ErrOAuthNonceMismatch
	}

	return redirectURI, nil
}

func (s *authService) OAuthLogin(ctx context.Context, dto domain.OAuthLoginDTO) (*domain.OAuthLoginResult, error) {
	redirectURI, err := s.VerifyOAuthState(ctx, domain.VerifyOAuthStateDTO{
		Provider: dto.Provider,
		State:    dto.State,
		Nonce:    dto.Nonce,
	})
	if err != nil {
		return nil, err
	}

	if dto.CodeVerifier == "" {
		return nil, ErrOAuthMissingCodeVerifier
	}

	providerUserInfo, err := s.GetOAuthProviderUserInfo(ctx, dto.Provider, dto.Code, dto.CodeVerifier)
	if err != nil {
		return nil, err
	}

	userInfo := *providerUserInfo
	userInfo.Email = normalizeEmail(userInfo.Email)

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

	authenticatedUser, linked, err := s.resolveOAuthUser(ctx, dto.Provider, &userInfo)
	if errors.Is(err, errOAuthEmailUnverified) {
		return s.startOAuthSignup(ctx, dto.Provider, &userInfo, redirectURI)
	}
	if err != nil {
		return nil, err
	}

	tokens, err := s.startSession(ctx, authenticatedUser)

	// Sent after the session starts so a slow send cannot leave a session the
	// client never receives; when the session fails the link is persisted anyway,
	// so the owner is still told.
	if linked != nil {
		s.notifyOAuthLinked(ctx, authenticatedUser, *linked)
	}

	if err != nil {
		return nil, domain.NewInternalServerError("auth.oauthLogin.tokenGenerationFailed", err)
	}

	return &domain.OAuthLoginResult{
		User:        authenticatedUser,
		Tokens:      tokens,
		RedirectURI: redirectURI,
	}, nil
}

func (s *authService) notifyOAuthLinked(ctx context.Context, user *domain.User, link domain.UserOAuthProvider) {
	err := s.emailVerification.SendOAuthLinkedNotice(ctx, user.Email, domain.OAuthLinkRevert{
		UserUUID: user.UUID,
		LinkUUID: link.UUID,
		Provider: link.Provider,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to send the OAuth link notice", "user_uuid", user.UUID, "error", err)
	}
}

// The link row is the only state of the undo token, so it is single use: once
// the link is gone (undone, or removed some other way) the token is stale.
func (s *authService) RevertOAuthLink(ctx context.Context, token string) (string, error) {
	revert, err := s.emailVerification.VerifyOAuthLinkRevertToken(ctx, token)
	if err != nil {
		return "", err
	}

	err = s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		deleted, err := s.authRepository.DeleteUserOAuthProviderOfUser(ctx, revert.UserUUID, revert.LinkUUID)
		if err != nil {
			return err
		}
		if !deleted {
			return errOAuthLinkStaleToken
		}
		return s.sessionsRepository.DeleteAllByUser(ctx, revert.UserUUID)
	})
	if err != nil {
		return "", err
	}

	return revert.UserUUID, nil
}

func (s *authService) startOAuthSignup(ctx context.Context, provider domain.OAuthProviderName, userInfo *domain.OAuthProviderUserInfo, redirectURI string) (*domain.OAuthLoginResult, error) {
	pendingUUID, err := s.pendingSignups.StartOAuth(ctx, domain.StartOAuthSignupDTO{
		Name:           userInfo.Name,
		Email:          userInfo.Email,
		Provider:       provider,
		ProviderUserID: userInfo.ID,
	})

	var tooManyErr *domain.TooManyRequestsError
	if errors.As(err, &tooManyErr) {
		return &domain.OAuthLoginResult{RedirectURI: redirectURI, VerificationLimited: true}, nil
	}
	if err != nil {
		return nil, err
	}

	return &domain.OAuthLoginResult{RedirectURI: redirectURI, PendingSignupUUID: pendingUUID}, nil
}

func (s *authService) resolveOAuthUser(ctx context.Context, provider domain.OAuthProviderName, userInfo *domain.OAuthProviderUserInfo) (*domain.User, *domain.UserOAuthProvider, error) {
	user, linked, err := s.resolveOAuthUserWithinTx(ctx, provider, userInfo)

	// A concurrent or replayed callback may have created the user or link first;
	// its transaction has committed, so resolving again finds the existing records.
	var conflictErr *domain.ConflictError
	if errors.As(err, &conflictErr) {
		return s.resolveOAuthUserWithinTx(ctx, provider, userInfo)
	}

	return user, linked, err
}

func (s *authService) resolveOAuthUserWithinTx(ctx context.Context, provider domain.OAuthProviderName, userInfo *domain.OAuthProviderUserInfo) (*domain.User, *domain.UserOAuthProvider, error) {
	var user *domain.User
	var linked *domain.UserOAuthProvider
	err := s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		user, linked, err = s.findOrCreateOAuthUser(ctx, provider, userInfo)
		return err
	})
	if err != nil {
		return nil, nil, err
	}

	return user, linked, nil
}

func (s *authService) findOrCreateOAuthUser(ctx context.Context, provider domain.OAuthProviderName, userInfo *domain.OAuthProviderUserInfo) (*domain.User, *domain.UserOAuthProvider, error) {
	var notFoundErr *domain.NotFoundError

	userOAuthProvider, err := s.GetUserOAuthProvider(ctx, domain.GetUserOAuthProviderDTO{
		Provider:       provider,
		ProviderUserID: userInfo.ID,
	})
	if err != nil && !errors.As(err, &notFoundErr) {
		return nil, nil, err
	}

	// Case 1: provider is already linked to a user.
	if userOAuthProvider != nil {
		user, err := s.usersService.GetByUUID(ctx, domain.Actor{UUID: userOAuthProvider.UserUUID}, userOAuthProvider.UserUUID)
		return user, nil, err
	}

	// Both Case 2 and Case 3 trust the provider's claim of owning this email;
	// otherwise the mailbox is proven by code before anything is written.
	if !userInfo.EmailVerified {
		return nil, nil, errOAuthEmailUnverified
	}

	existingUser, err := s.usersService.GetByEmail(ctx, userInfo.Email)
	if err != nil && !errors.As(err, &notFoundErr) {
		return nil, nil, err
	}

	// Case 2: provider email matches an existing user account (link provider).
	// Every account proved its email when it was created, so the provider and
	// the account belong to the same mailbox owner. The created link is returned
	// so the caller can notify the owner once the transaction committed.
	if existingUser != nil {
		link, err := s.AddUserOAuthProvider(ctx, domain.AddUserOAuthProviderDTO{
			UserUUID:       existingUser.UUID,
			Provider:       provider,
			ProviderUserID: userInfo.ID,
			ProviderEmail:  userInfo.Email,
		})
		if err != nil {
			return nil, nil, err
		}

		return existingUser, link, nil
	}

	// Case 3: provider is not used and there is no user with this email (create user and link).
	newUser, err := s.usersService.CreateOAuth(ctx, domain.CreateOAuthUserDTO{
		Name:  userInfo.Name,
		Email: userInfo.Email,
	})
	if err != nil {
		return nil, nil, err
	}

	if _, err := s.AddUserOAuthProvider(ctx, domain.AddUserOAuthProviderDTO{
		UserUUID:       newUser.UUID,
		Provider:       provider,
		ProviderUserID: userInfo.ID,
		ProviderEmail:  userInfo.Email,
	}); err != nil {
		return nil, nil, err
	}

	return newUser, nil, nil
}
