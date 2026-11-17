package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	selfActor  = domain.Actor{UUID: "some-uuid", Role: domain.RoleUser}
	adminActor = domain.Actor{UUID: "admin-uuid", Role: domain.RoleAdmin}
	otherActor = domain.Actor{UUID: "other-uuid", Role: domain.RoleUser}
)

func TestNewUserService(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)
	assert.NotNil(t, service)
}

func TestUsersService_GetByUUID(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)

	t.Run("self is allowed", func(t *testing.T) {
		user := &domain.User{UUID: "some-uuid", Name: "Test User"}
		repo.On("FindByUUID", "some-uuid").Return(user, nil).Once()

		result, err := service.GetByUUID(context.Background(), selfActor, "some-uuid")

		assert.NoError(t, err)
		assert.Equal(t, user, result)
		repo.AssertExpectations(t)
	})

	t.Run("admin is allowed", func(t *testing.T) {
		user := &domain.User{UUID: "some-uuid", Name: "Test User"}
		repo.On("FindByUUID", "some-uuid").Return(user, nil).Once()

		result, err := service.GetByUUID(context.Background(), adminActor, "some-uuid")

		assert.NoError(t, err)
		assert.Equal(t, user, result)
		repo.AssertExpectations(t)
	})

	t.Run("other user is forbidden", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)

		result, err := service.GetByUUID(context.Background(), otherActor, "some-uuid")

		var forbiddenErr *domain.ForbiddenError
		assert.True(t, errors.As(err, &forbiddenErr))
		assert.Nil(t, result)
		repo.AssertNotCalled(t, "FindByUUID", "some-uuid")
	})

	t.Run("not found", func(t *testing.T) {
		repo.On("FindByUUID", "not-found-uuid").Return(nil, errors.New("not found")).Once()

		result, err := service.GetByUUID(context.Background(), adminActor, "not-found-uuid")

		assert.Error(t, err)
		assert.Nil(t, result)
		repo.AssertExpectations(t)
	})
}

func TestUsersService_GetByEmail(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)

	t.Run("success", func(t *testing.T) {
		user := &domain.User{UUID: "some-uuid", Name: "Test User", Email: "test@example.com"}
		repo.On("FindByEmail", "test@example.com").Return(user, nil).Once()

		result, err := service.GetByEmail(context.Background(), "test@example.com")

		assert.NoError(t, err)
		assert.Equal(t, user, result)
		repo.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		repo.On("FindByEmail", "not-found@example.com").Return(nil, errors.New("not found")).Once()

		result, err := service.GetByEmail(context.Background(), "not-found@example.com")

		assert.Error(t, err)
		assert.Nil(t, result)
		repo.AssertExpectations(t)
	})
}

func TestUsersService_Create(t *testing.T) {
	dto := domain.CreateUserDTO{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "password123",
	}
	created := &domain.User{
		UUID:         "generated-uuid",
		Name:         "Test User",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		Role:         domain.RoleUser,
		CreatedAt:    1234567890,
	}

	t.Run("success sends the verification email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		sender := new(mocks.EmailVerificationServiceMock)
		service := services.NewUserService(repo, sender, nil, nil, nil)
		repo.On("Create", mock.MatchedBy(func(u domain.User) bool {
			return u.Role == domain.RoleUser
		})).Return(created, nil).Once()
		sender.On("SendVerificationEmail", mock.Anything, created).Return(nil).Once()

		user, err := service.Create(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "generated-uuid", user.UUID)
		assert.Equal(t, dto.Name, user.Name)
		assert.Equal(t, dto.Email, user.Email)
		assert.Equal(t, "hashed-password", user.PasswordHash)
		assert.Equal(t, domain.RoleUser, user.Role)
		assert.Equal(t, int64(1234567890), user.CreatedAt)
		repo.AssertExpectations(t)
		sender.AssertExpectations(t)
		sender.AssertNumberOfCalls(t, "SendVerificationEmail", 1)
	})

	t.Run("verification email failure does not fail creation", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		sender := new(mocks.EmailVerificationServiceMock)
		service := services.NewUserService(repo, sender, nil, nil, nil)
		repo.On("Create", mock.AnythingOfType("domain.User")).Return(created, nil).Once()
		sender.On("SendVerificationEmail", mock.Anything, created).Return(errors.New("smtp down")).Once()

		user, err := service.Create(context.Background(), dto)

		assert.NoError(t, err)
		assert.Equal(t, created, user)
		sender.AssertExpectations(t)
	})

	t.Run("success oauth (no password) does not send the verification email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		sender := new(mocks.EmailVerificationServiceMock)
		service := services.NewUserService(repo, sender, nil, nil, nil)
		dto := domain.CreateOAuthUserDTO{
			Name:  "Test User",
			Email: "test@example.com",
		}

		repo.On("Create", mock.MatchedBy(func(u domain.User) bool {
			return u.Role == domain.RoleUser && u.PasswordHash == ""
		})).Return(&domain.User{
			UUID:         "generated-uuid",
			Name:         "Test User",
			Email:        "test@example.com",
			PasswordHash: "",
			Role:         domain.RoleUser,
			CreatedAt:    1234567890,
		}, nil).Once()

		user, err := service.CreateOAuth(context.Background(), dto)

		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "generated-uuid", user.UUID)
		assert.Equal(t, dto.Name, user.Name)
		assert.Equal(t, dto.Email, user.Email)
		assert.Equal(t, "", user.PasswordHash)
		assert.Equal(t, domain.RoleUser, user.Role)
		assert.Equal(t, int64(1234567890), user.CreatedAt)
		repo.AssertExpectations(t)
		sender.AssertNotCalled(t, "SendVerificationEmail", mock.Anything, mock.Anything)
	})

	t.Run("repository create error", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		sender := new(mocks.EmailVerificationServiceMock)
		service := services.NewUserService(repo, sender, nil, nil, nil)
		repo.On("Create", mock.AnythingOfType("domain.User")).Return(nil, errors.New("db error")).Once()

		user, err := service.Create(context.Background(), dto)

		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		assert.Nil(t, user)
		repo.AssertExpectations(t)
		sender.AssertNotCalled(t, "SendVerificationEmail", mock.Anything, mock.Anything)
	})
}

func TestUsersService_Update(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)
	uuid := "some-uuid"
	originalUser := &domain.User{
		UUID:  uuid,
		Name:  "Original Name",
		Email: "original@example.com",
	}

	t.Run("success", func(t *testing.T) {
		newName := "New Name"
		dto := domain.UserUpdateDTO{Name: &newName}

		repo.On("FindByUUID", uuid).Return(originalUser, nil).Once()
		updatedUser := &domain.User{UUID: uuid, Name: newName, Email: originalUser.Email}
		repo.On("Update", mock.MatchedBy(func(u domain.User) bool {
			return u.Name == newName && u.Email == originalUser.Email
		})).Return(updatedUser, nil).Once()

		user, err := service.Update(context.Background(), selfActor, uuid, dto)

		assert.NoError(t, err)
		assert.Equal(t, updatedUser, user)
		repo.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		dto := domain.UserUpdateDTO{}
		repo.On("FindByUUID", "not-found").Return(nil, errors.New("not found")).Once()

		user, err := service.Update(context.Background(), adminActor, "not-found", dto)

		assert.Error(t, err)
		assert.Nil(t, user)
		repo.AssertExpectations(t)
	})

	t.Run("update fails", func(t *testing.T) {
		newName := "New Name"
		dto := domain.UserUpdateDTO{Name: &newName}

		repo.On("FindByUUID", uuid).Return(originalUser, nil).Once()
		repo.On("Update", mock.AnythingOfType("domain.User")).Return(nil, errors.New("db error")).Once()

		user, err := service.Update(context.Background(), selfActor, uuid, dto)

		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, "db error", err.Error())
		repo.AssertExpectations(t)
	})

	t.Run("admin is allowed", func(t *testing.T) {
		name := "New Name"
		dto := domain.UserUpdateDTO{Name: &name}
		repo.On("FindByUUID", uuid).Return(&domain.User{UUID: uuid}, nil).Once()
		repo.On("Update", mock.AnythingOfType("domain.User")).Return(&domain.User{UUID: uuid}, nil).Once()

		user, err := service.Update(context.Background(), adminActor, uuid, dto)

		assert.NoError(t, err)
		assert.NotNil(t, user)
		repo.AssertExpectations(t)
	})

	t.Run("other user is forbidden", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)
		name := "New Name"
		dto := domain.UserUpdateDTO{Name: &name}

		user, err := service.Update(context.Background(), otherActor, uuid, dto)

		assert.Nil(t, user)
		var forbiddenErr *domain.ForbiddenError
		assert.True(t, errors.As(err, &forbiddenErr))
		repo.AssertNotCalled(t, "FindByUUID", uuid)
		repo.AssertNotCalled(t, "Update", mock.Anything)
	})
}

func TestUsersService_Delete(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)
	uuid := "some-uuid"

	t.Run("success", func(t *testing.T) {
		repo.On("Delete", uuid).Return(nil).Once()

		err := service.Delete(context.Background(), selfActor, uuid)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("delete fails", func(t *testing.T) {
		repo.On("Delete", uuid).Return(errors.New("db error")).Once()

		err := service.Delete(context.Background(), selfActor, uuid)

		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		repo.AssertExpectations(t)
	})

	t.Run("admin is allowed", func(t *testing.T) {
		repo.On("Delete", uuid).Return(nil).Once()

		err := service.Delete(context.Background(), adminActor, uuid)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("other user is forbidden", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)

		err := service.Delete(context.Background(), otherActor, uuid)

		var forbiddenErr *domain.ForbiddenError
		assert.True(t, errors.As(err, &forbiddenErr))
		repo.AssertNotCalled(t, "Delete", uuid)
	})
}

func newVerificationUsersService() (domain.UsersService, *mocks.UsersRepositoryMock, *mocks.EmailVerificationServiceMock) {
	repo := new(mocks.UsersRepositoryMock)
	emailVerification := new(mocks.EmailVerificationServiceMock)
	return services.NewUserService(repo, emailVerification, nil, nil, nil), repo, emailVerification
}

func TestUsersService_VerifyEmail(t *testing.T) {
	t.Run("marks unverified user as verified", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		emailVerification.On("VerifyVerificationToken", "token").Return("user-uuid", nil).Once()
		repo.On("FindByUUID", "user-uuid").Return(&domain.User{UUID: "user-uuid"}, nil).Once()
		repo.On("MarkEmailVerified", "user-uuid").Return(nil).Once()

		err := service.VerifyEmail(context.Background(), "token")

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("already verified is idempotent", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		emailVerification.On("VerifyVerificationToken", "token").Return("user-uuid", nil).Once()
		repo.On("FindByUUID", "user-uuid").Return(&domain.User{UUID: "user-uuid", EmailVerified: true}, nil).Once()

		err := service.VerifyEmail(context.Background(), "token")

		assert.NoError(t, err)
		repo.AssertNotCalled(t, "MarkEmailVerified", mock.Anything)
	})

	t.Run("invalid token", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		emailVerification.On("VerifyVerificationToken", "token").Return("", services.ErrInvalidToken).Once()

		err := service.VerifyEmail(context.Background(), "token")

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		repo.AssertNotCalled(t, "FindByUUID", mock.Anything)
	})

	t.Run("unknown user", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		notFound := domain.NewNotFoundError("users.notFound")
		emailVerification.On("VerifyVerificationToken", "token").Return("ghost", nil).Once()
		repo.On("FindByUUID", "ghost").Return(nil, notFound).Once()

		err := service.VerifyEmail(context.Background(), "token")

		assert.ErrorIs(t, err, notFound)
		repo.AssertNotCalled(t, "MarkEmailVerified", mock.Anything)
	})

	t.Run("mark error", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		markErr := errors.New("db error")
		emailVerification.On("VerifyVerificationToken", "token").Return("user-uuid", nil).Once()
		repo.On("FindByUUID", "user-uuid").Return(&domain.User{UUID: "user-uuid"}, nil).Once()
		repo.On("MarkEmailVerified", "user-uuid").Return(markErr).Once()

		err := service.VerifyEmail(context.Background(), "token")

		assert.ErrorIs(t, err, markErr)
	})
}

func TestUsersService_ResendVerification(t *testing.T) {
	t.Run("sends for unverified user", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		user := &domain.User{UUID: "user-uuid", Email: "test@example.com"}
		repo.On("FindByEmail", "test@example.com").Return(user, nil).Once()
		emailVerification.On("SendVerificationEmail", mock.Anything, user).Return(nil).Once()

		err := service.ResendVerification(context.Background(), "test@example.com")

		assert.NoError(t, err)
		emailVerification.AssertExpectations(t)
	})

	t.Run("unknown email succeeds silently", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		repo.On("FindByEmail", "ghost@example.com").Return(nil, domain.NewNotFoundError("users.notFound")).Once()

		err := service.ResendVerification(context.Background(), "ghost@example.com")

		assert.NoError(t, err)
		emailVerification.AssertNotCalled(t, "SendVerificationEmail", mock.Anything, mock.Anything)
	})

	t.Run("already verified succeeds silently", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		repo.On("FindByEmail", "test@example.com").Return(&domain.User{UUID: "user-uuid", Email: "test@example.com", EmailVerified: true}, nil).Once()

		err := service.ResendVerification(context.Background(), "test@example.com")

		assert.NoError(t, err)
		emailVerification.AssertNotCalled(t, "SendVerificationEmail", mock.Anything, mock.Anything)
	})

	t.Run("lookup error is returned", func(t *testing.T) {
		service, repo, _ := newVerificationUsersService()
		lookupErr := errors.New("db error")
		repo.On("FindByEmail", "test@example.com").Return(nil, lookupErr).Once()

		err := service.ResendVerification(context.Background(), "test@example.com")

		assert.ErrorIs(t, err, lookupErr)
	})

	t.Run("send error is returned", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		sendErr := errors.New("smtp down")
		repo.On("FindByEmail", "test@example.com").Return(&domain.User{UUID: "user-uuid", Email: "test@example.com"}, nil).Once()
		emailVerification.On("SendVerificationEmail", mock.Anything, mock.Anything).Return(sendErr).Once()

		err := service.ResendVerification(context.Background(), "test@example.com")

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestUsersService_CreateOAuth_EmailVerified(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock), nil, nil, nil)

	for _, verified := range []bool{true, false} {
		repo.On("Create", mock.MatchedBy(func(u domain.User) bool {
			return u.EmailVerified == verified
		})).Return(&domain.User{UUID: "uuid", EmailVerified: verified}, nil).Once()

		user, err := service.CreateOAuth(context.Background(), domain.CreateOAuthUserDTO{
			Name:          "Test",
			Email:         "test@example.com",
			EmailVerified: verified,
		})

		assert.NoError(t, err)
		assert.Equal(t, verified, user.EmailVerified)
	}
}

func TestUsersService_RequestEmailChange(t *testing.T) {
	user := &domain.User{UUID: selfActor.UUID, Email: "old@example.com"}

	t.Run("success sends the confirmation to the normalized new email", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()
		repo.On("FindByEmail", "new@example.com").Return(nil, domain.NewNotFoundError("users.notFound")).Once()
		emailVerification.On("SendEmailChangeEmail", user, "new@example.com").Return(nil).Once()

		err := service.RequestEmailChange(context.Background(), selfActor, "  New@Example.com ")

		assert.NoError(t, err)
		repo.AssertExpectations(t)
		emailVerification.AssertExpectations(t)
	})

	t.Run("error - locked after a recent change", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		locked := *user
		locked.EmailChangedAt = time.Now().Add(-time.Hour).Unix()
		repo.On("FindByUUID", selfActor.UUID).Return(&locked, nil).Once()

		err := service.RequestEmailChange(context.Background(), selfActor, "new@example.com")

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.emailChange.locked", conflictErr.Error())
		emailVerification.AssertNotCalled(t, "SendEmailChangeEmail", mock.Anything, mock.Anything)
	})

	t.Run("error - unauthenticated actor", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()

		err := service.RequestEmailChange(context.Background(), domain.Actor{}, "new@example.com")

		var unauthorizedErr *domain.UnauthorizedError
		assert.True(t, errors.As(err, &unauthorizedErr))
		repo.AssertNotCalled(t, "FindByUUID", mock.Anything)
		emailVerification.AssertNotCalled(t, "SendEmailChangeEmail", mock.Anything, mock.Anything)
	})

	t.Run("error - same email", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()

		err := service.RequestEmailChange(context.Background(), selfActor, "OLD@example.com")

		var validationErr *domain.ValidationError
		require.True(t, errors.As(err, &validationErr))
		assert.Equal(t, "users.emailChange.unchanged", validationErr.Error())
		repo.AssertNotCalled(t, "FindByEmail", mock.Anything)
		emailVerification.AssertNotCalled(t, "SendEmailChangeEmail", mock.Anything, mock.Anything)
	})

	t.Run("error - email taken", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()
		repo.On("FindByEmail", "taken@example.com").Return(&domain.User{UUID: "other"}, nil).Once()

		err := service.RequestEmailChange(context.Background(), selfActor, "taken@example.com")

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())
		emailVerification.AssertNotCalled(t, "SendEmailChangeEmail", mock.Anything, mock.Anything)
	})

	t.Run("error - user lookup fails", func(t *testing.T) {
		service, repo, _ := newVerificationUsersService()
		notFound := domain.NewNotFoundError("users.notFound")
		repo.On("FindByUUID", selfActor.UUID).Return(nil, notFound).Once()

		err := service.RequestEmailChange(context.Background(), selfActor, "new@example.com")

		assert.ErrorIs(t, err, notFound)
	})

	t.Run("error - email lookup fails", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		dbErr := errors.New("db error")
		repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()
		repo.On("FindByEmail", "new@example.com").Return(nil, dbErr).Once()

		err := service.RequestEmailChange(context.Background(), selfActor, "new@example.com")

		assert.ErrorIs(t, err, dbErr)
		emailVerification.AssertNotCalled(t, "SendEmailChangeEmail", mock.Anything, mock.Anything)
	})

	t.Run("error - send fails", func(t *testing.T) {
		service, repo, emailVerification := newVerificationUsersService()
		sendErr := errors.New("smtp down")
		repo.On("FindByUUID", selfActor.UUID).Return(user, nil).Once()
		repo.On("FindByEmail", "new@example.com").Return(nil, domain.NewNotFoundError("users.notFound")).Once()
		emailVerification.On("SendEmailChangeEmail", user, "new@example.com").Return(sendErr).Once()

		err := service.RequestEmailChange(context.Background(), selfActor, "new@example.com")

		assert.ErrorIs(t, err, sendErr)
	})
}

type emailChangeFixture struct {
	service           domain.UsersService
	repo              *mocks.UsersRepositoryMock
	sessions          *mocks.SessionsRepositoryMock
	authRepo          *mocks.AuthRepositoryMock
	emailVerification *mocks.EmailVerificationServiceMock
}

func newEmailChangeFixture() emailChangeFixture {
	f := emailChangeFixture{
		repo:              new(mocks.UsersRepositoryMock),
		sessions:          new(mocks.SessionsRepositoryMock),
		authRepo:          new(mocks.AuthRepositoryMock),
		emailVerification: new(mocks.EmailVerificationServiceMock),
	}
	f.service = services.NewUserService(f.repo, f.emailVerification, f.sessions, f.authRepo, newTransactorMock())
	return f
}

func TestUsersService_ConfirmEmailChange(t *testing.T) {
	change := &domain.EmailChange{UserUUID: "user-uuid", CurrentEmail: "old@example.com", NewEmail: "new@example.com", Version: 3}
	user := &domain.User{UUID: "user-uuid", Email: "old@example.com", EmailVersion: 3}
	changedAt := time.Now().Unix()
	updated := &domain.User{UUID: "user-uuid", Email: "new@example.com", EmailVerified: true, EmailVersion: 4, EmailChangedAt: changedAt}

	expectUpdate := func(f emailChangeFixture) {
		f.emailVerification.On("VerifyEmailChangeToken", "token").Return(change, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(user, nil).Once()
		f.repo.On("UpdateEmail", "user-uuid", "new@example.com", 3, mock.MatchedBy(func(at *time.Time) bool {
			return at != nil && time.Since(*at) < time.Minute
		})).Return(updated, nil).Once()
	}
	notice := domain.EmailChangeRevert{UserUUID: "user-uuid", OldEmail: "old@example.com", NewEmail: "new@example.com", Version: 4, ChangedAt: changedAt}

	t.Run("success updates the email, revokes every session and notifies the old address", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectUpdate(f)
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.emailVerification.On("SendEmailChangedNotice", notice).Return(nil).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), "token")

		assert.NoError(t, err)
		assert.Equal(t, updated, result)
		f.repo.AssertExpectations(t)
		f.sessions.AssertExpectations(t)
		f.emailVerification.AssertExpectations(t)
	})

	t.Run("success - an expired lock does not block", func(t *testing.T) {
		f := newEmailChangeFixture()
		locked := *user
		locked.EmailChangedAt = time.Now().Add(-domain.EmailChangeLock - time.Hour).Unix()
		f.emailVerification.On("VerifyEmailChangeToken", "token").Return(change, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(&locked, nil).Once()
		f.repo.On("UpdateEmail", "user-uuid", "new@example.com", 3, mock.Anything).Return(updated, nil).Once()
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.emailVerification.On("SendEmailChangedNotice", notice).Return(nil).Once()

		_, err := f.service.ConfirmEmailChange(context.Background(), "token")

		assert.NoError(t, err)
	})

	t.Run("success - notice failure does not fail the change", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectUpdate(f)
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.emailVerification.On("SendEmailChangedNotice", notice).Return(errors.New("smtp down")).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), "token")

		assert.NoError(t, err)
		assert.Equal(t, updated, result)
	})

	t.Run("error - invalid token", func(t *testing.T) {
		f := newEmailChangeFixture()
		f.emailVerification.On("VerifyEmailChangeToken", "token").Return(nil, services.ErrInvalidToken).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Nil(t, result)
		f.repo.AssertNotCalled(t, "FindByUUID", mock.Anything)
	})

	staleCases := map[string]*domain.User{
		"current email no longer matches": {UUID: "user-uuid", Email: "other@example.com", EmailVersion: 3},
		"version moved on (A to B to A)":  {UUID: "user-uuid", Email: "old@example.com", EmailVersion: 5},
	}
	for name, staleUser := range staleCases {
		t.Run("error - stale token: "+name, func(t *testing.T) {
			f := newEmailChangeFixture()
			f.emailVerification.On("VerifyEmailChangeToken", "token").Return(change, nil).Once()
			f.repo.On("FindByUUID", "user-uuid").Return(staleUser, nil).Once()

			result, err := f.service.ConfirmEmailChange(context.Background(), "token")

			var unauthorizedErr *domain.UnauthorizedError
			require.True(t, errors.As(err, &unauthorizedErr))
			assert.Equal(t, "users.emailChange.staleToken", unauthorizedErr.Error())
			assert.Nil(t, result)
			f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			f.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
		})
	}

	t.Run("error - locked after a recent change", func(t *testing.T) {
		f := newEmailChangeFixture()
		locked := *user
		locked.EmailChangedAt = time.Now().Add(-time.Hour).Unix()
		f.emailVerification.On("VerifyEmailChangeToken", "token").Return(change, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(&locked, nil).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), "token")

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.emailChange.locked", conflictErr.Error())
		assert.Nil(t, result)
		f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("error - unknown user", func(t *testing.T) {
		f := newEmailChangeFixture()
		notFound := domain.NewNotFoundError("users.notFound")
		f.emailVerification.On("VerifyEmailChangeToken", "token").Return(change, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(nil, notFound).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, notFound)
		assert.Nil(t, result)
	})

	t.Run("error - update conflict", func(t *testing.T) {
		f := newEmailChangeFixture()
		conflict := domain.NewConflictError("users.email.conflict")
		f.emailVerification.On("VerifyEmailChangeToken", "token").Return(change, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(user, nil).Once()
		f.repo.On("UpdateEmail", "user-uuid", "new@example.com", 3, mock.Anything).Return(nil, conflict).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, conflict)
		assert.Nil(t, result)
		f.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
		f.emailVerification.AssertNotCalled(t, "SendEmailChangedNotice", mock.Anything)
	})

	t.Run("error - session revocation failure", func(t *testing.T) {
		f := newEmailChangeFixture()
		deleteErr := errors.New("db error")
		expectUpdate(f)
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(deleteErr).Once()

		result, err := f.service.ConfirmEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, deleteErr)
		assert.Nil(t, result)
		f.emailVerification.AssertNotCalled(t, "SendEmailChangedNotice", mock.Anything)
	})
}

func TestUsersService_RevertEmailChange(t *testing.T) {
	changedAt := time.Now().Add(-time.Hour).Unix()
	revert := &domain.EmailChangeRevert{UserUUID: "user-uuid", OldEmail: "old@example.com", NewEmail: "new@example.com", Version: 4, ChangedAt: changedAt}
	user := &domain.User{UUID: "user-uuid", Email: "new@example.com", EmailVersion: 4, EmailChangedAt: changedAt}
	restored := &domain.User{UUID: "user-uuid", Email: "old@example.com", EmailVersion: 5}

	expectLoad := func(f emailChangeFixture) {
		f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(revert, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(user, nil).Once()
	}

	t.Run("success restores the old email, clears the lock and revokes sessions and linked providers", func(t *testing.T) {
		f := newEmailChangeFixture()
		expectLoad(f)
		f.repo.On("UpdateEmail", "user-uuid", "old@example.com", 4, (*time.Time)(nil)).Return(restored, nil).Once()
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.authRepo.On("DeleteOAuthProvidersCreatedSince", "user-uuid", time.Unix(changedAt, 0)).Return(nil).Once()

		err := f.service.RevertEmailChange(context.Background(), "token")

		assert.NoError(t, err)
		f.repo.AssertExpectations(t)
		f.sessions.AssertExpectations(t)
		f.authRepo.AssertExpectations(t)
	})

	t.Run("error - invalid token", func(t *testing.T) {
		f := newEmailChangeFixture()
		f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(nil, services.ErrInvalidToken).Once()

		err := f.service.RevertEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, services.ErrInvalidToken)
	})

	staleCases := map[string]*domain.User{
		"replayed after the revert":     {UUID: "user-uuid", Email: "old@example.com", EmailVersion: 5},
		"email differs from the change": {UUID: "user-uuid", Email: "other@example.com", EmailVersion: 4},
	}
	for name, staleUser := range staleCases {
		t.Run("error - stale token: "+name, func(t *testing.T) {
			f := newEmailChangeFixture()
			f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(revert, nil).Once()
			f.repo.On("FindByUUID", "user-uuid").Return(staleUser, nil).Once()

			err := f.service.RevertEmailChange(context.Background(), "token")

			var unauthorizedErr *domain.UnauthorizedError
			require.True(t, errors.As(err, &unauthorizedErr))
			assert.Equal(t, "users.emailChange.staleToken", unauthorizedErr.Error())
			f.repo.AssertNotCalled(t, "UpdateEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}

	t.Run("error - unknown user", func(t *testing.T) {
		f := newEmailChangeFixture()
		notFound := domain.NewNotFoundError("users.notFound")
		f.emailVerification.On("VerifyEmailChangeRevertToken", "token").Return(revert, nil).Once()
		f.repo.On("FindByUUID", "user-uuid").Return(nil, notFound).Once()

		err := f.service.RevertEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, notFound)
	})

	t.Run("error - old email taken meanwhile", func(t *testing.T) {
		f := newEmailChangeFixture()
		conflict := domain.NewConflictError("users.email.conflict")
		expectLoad(f)
		f.repo.On("UpdateEmail", "user-uuid", "old@example.com", 4, (*time.Time)(nil)).Return(nil, conflict).Once()

		err := f.service.RevertEmailChange(context.Background(), "token")

		assert.Equal(t, conflict, err)
		f.sessions.AssertNotCalled(t, "DeleteAllByUser", mock.Anything)
	})

	t.Run("error - transaction step failure", func(t *testing.T) {
		f := newEmailChangeFixture()
		deleteErr := errors.New("db error")
		expectLoad(f)
		f.repo.On("UpdateEmail", "user-uuid", "old@example.com", 4, (*time.Time)(nil)).Return(restored, nil).Once()
		f.sessions.On("DeleteAllByUser", "user-uuid").Return(nil).Once()
		f.authRepo.On("DeleteOAuthProvidersCreatedSince", "user-uuid", mock.Anything).Return(deleteErr).Once()

		err := f.service.RevertEmailChange(context.Background(), "token")

		assert.ErrorIs(t, err, deleteErr)
	})
}
