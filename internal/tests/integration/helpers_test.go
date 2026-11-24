package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/require"
)

type failingTrimSessionsRepository struct {
	domain.SessionsRepository
	err error
}

func (r failingTrimSessionsRepository) DeleteOldestBeyond(context.Context, string, int) error {
	return r.err
}

type failingDeleteAllSessionsRepository struct {
	domain.SessionsRepository
	err error
}

func (r failingDeleteAllSessionsRepository) DeleteAllByUser(context.Context, string) error {
	return r.err
}

type blockingDeleteAllSessionsRepository struct {
	domain.SessionsRepository
	reached chan struct{}
	release chan struct{}
}

func (r blockingDeleteAllSessionsRepository) DeleteAllByUser(ctx context.Context, userUUID string) error {
	close(r.reached)
	<-r.release
	return r.SessionsRepository.DeleteAllByUser(ctx, userUUID)
}

type failingDeleteProvidersAuthRepository struct {
	domain.AuthRepository
	err error
}

func (r failingDeleteProvidersAuthRepository) DeleteOAuthProvidersCreatedSince(context.Context, string, time.Time) error {
	return r.err
}

type failingLinkAuthRepository struct {
	domain.AuthRepository
	err error
}

func (r failingLinkAuthRepository) CreateUserOAuthProvider(context.Context, domain.UserOAuthProvider) (*domain.UserOAuthProvider, error) {
	return nil, r.err
}

type failingDeleteOthersSessionsRepository struct {
	domain.SessionsRepository
	err error
}

func (r failingDeleteOthersSessionsRepository) DeleteOthersByUser(context.Context, string, string) error {
	return r.err
}

type failingStepUpSessionsRepository struct {
	domain.SessionsRepository
	err error
}

func (r failingStepUpSessionsRepository) SetStepUpUntil(context.Context, string, string, time.Time) error {
	return r.err
}

func seedSession(t *testing.T, repo domain.SessionsRepository, userUUID string, jti string) *domain.UserSession {
	t.Helper()
	session, err := repo.Create(context.Background(), domain.UserSession{
		UserUUID:   userUUID,
		CurrentJTI: jti,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	return session
}

func setSessionTimes(t *testing.T, sessionUUID string, lastUsedAt time.Time, expiresAt time.Time) {
	t.Helper()
	_, err := testDB.Exec(context.Background(),
		"UPDATE user_sessions SET last_used_at = $2, expires_at = $3 WHERE uuid = $1",
		sessionUUID, lastUsedAt, expiresAt,
	)
	require.NoError(t, err)
}

func sessionExists(t *testing.T, repo domain.SessionsRepository, userUUID string, sessionUUID string) bool {
	t.Helper()
	_, err := repo.FindByUUID(context.Background(), userUUID, sessionUUID)
	if err == nil {
		return true
	}
	var notFoundErr *domain.NotFoundError
	require.True(t, errors.As(err, &notFoundErr), "unexpected error: %v", err)
	return false
}

func passwordResetAttempts(t *testing.T, resetUUID string) int {
	t.Helper()
	var attempts int
	require.NoError(t, testDB.QueryRow(context.Background(), "SELECT attempts FROM password_resets WHERE uuid = $1", resetUUID).Scan(&attempts))
	return attempts
}

func countPasswordResets(t *testing.T) int {
	t.Helper()
	var count int
	require.NoError(t, testDB.QueryRow(context.Background(), "SELECT count(*) FROM password_resets").Scan(&count))
	return count
}

func pendingSignupAttempts(t *testing.T, pendingUUID string) int {
	var attempts int
	require.NoError(t, testDB.QueryRow(context.Background(), "SELECT attempts FROM pending_signups WHERE uuid = $1", pendingUUID).Scan(&attempts))
	return attempts
}
