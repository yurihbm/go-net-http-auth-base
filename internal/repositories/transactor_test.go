package repositories_test

import (
	"context"
	"errors"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTransactorTest(t *testing.T) (domain.Transactor, domain.UsersRepository) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	truncateTables(context.Background(), testDB)

	transactor := repositories.NewPostgresTransactor(testDB)
	usersRepo := repositories.NewUsersPostgresRepository(repositories.NewTxAwareDB(testDB))

	return transactor, usersRepo
}

func newTransactorTestUser(email string) domain.User {
	return domain.User{Name: "Test User", Email: email, PasswordHash: "hashed_password"}
}

func TestPostgresTransactor_WithinTx(t *testing.T) {
	transactor, usersRepo := setupTransactorTest(t)

	t.Run("commits writes when fn succeeds", func(t *testing.T) {
		err := transactor.WithinTx(context.Background(), func(ctx context.Context) error {
			_, err := usersRepo.Create(ctx, newTransactorTestUser("commit@example.com"))
			return err
		})

		require.NoError(t, err)
		found, err := usersRepo.FindByEmail(context.Background(), "commit@example.com")
		require.NoError(t, err)
		assert.Equal(t, "commit@example.com", found.Email)
	})

	t.Run("rolls back writes and returns the error when fn fails", func(t *testing.T) {
		sentinel := errors.New("boom")

		err := transactor.WithinTx(context.Background(), func(ctx context.Context) error {
			if _, err := usersRepo.Create(ctx, newTransactorTestUser("rollback@example.com")); err != nil {
				return err
			}
			return sentinel
		})

		assert.Equal(t, sentinel, err)
		_, err = usersRepo.FindByEmail(context.Background(), "rollback@example.com")
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("rolls back writes and re-panics when fn panics", func(t *testing.T) {
		assert.PanicsWithValue(t, "boom", func() {
			_ = transactor.WithinTx(context.Background(), func(ctx context.Context) error {
				if _, err := usersRepo.Create(ctx, newTransactorTestUser("panic@example.com")); err != nil {
					return err
				}
				panic("boom")
			})
		})

		_, err := usersRepo.FindByEmail(context.Background(), "panic@example.com")
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("nested call joins the outer transaction", func(t *testing.T) {
		sentinel := errors.New("outer failure")

		err := transactor.WithinTx(context.Background(), func(ctx context.Context) error {
			innerErr := transactor.WithinTx(ctx, func(ctx context.Context) error {
				_, err := usersRepo.Create(ctx, newTransactorTestUser("nested@example.com"))
				return err
			})
			require.NoError(t, innerErr)
			return sentinel
		})

		assert.Equal(t, sentinel, err)
		_, err = usersRepo.FindByEmail(context.Background(), "nested@example.com")
		var notFoundErr *domain.NotFoundError
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("writes outside a transaction go straight to the pool", func(t *testing.T) {
		_, err := usersRepo.Create(context.Background(), newTransactorTestUser("pool@example.com"))
		require.NoError(t, err)

		found, err := usersRepo.FindByEmail(context.Background(), "pool@example.com")
		require.NoError(t, err)
		assert.Equal(t, "pool@example.com", found.Email)
	})
}
