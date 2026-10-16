package services_test

import (
	"context"
	"errors"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	selfActor  = domain.Actor{UUID: "some-uuid", Role: domain.RoleUser}
	adminActor = domain.Actor{UUID: "admin-uuid", Role: domain.RoleAdmin}
	otherActor = domain.Actor{UUID: "other-uuid", Role: domain.RoleUser}
)

func TestNewUserService(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))
	assert.NotNil(t, service)
}

func TestUsersService_GetByUUID(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))

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
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))

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
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))

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
		service := services.NewUserService(repo, sender)
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
		service := services.NewUserService(repo, sender)
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
		service := services.NewUserService(repo, sender)
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
		service := services.NewUserService(repo, sender)
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
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))
	uuid := "some-uuid"
	originalUser := &domain.User{
		UUID:  uuid,
		Name:  "Original Name",
		Email: "original@example.com",
	}

	t.Run("success", func(t *testing.T) {
		newName := "New Name"
		newEmail := "new@example.com"
		dto := domain.UserUpdateDTO{
			Name:  &newName,
			Email: &newEmail,
		}

		repo.On("FindByUUID", uuid).Return(originalUser, nil).Once()
		repo.On("Update", mock.MatchedBy(func(u domain.User) bool {
			return u.Name == newName && u.Email == newEmail
		})).Return(nil).Once()

		err := service.Update(context.Background(), selfActor, uuid, dto)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		dto := domain.UserUpdateDTO{}
		repo.On("FindByUUID", "not-found").Return(nil, errors.New("not found")).Once()

		err := service.Update(context.Background(), adminActor, "not-found", dto)

		assert.Error(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("update fails", func(t *testing.T) {
		newName := "New Name"
		dto := domain.UserUpdateDTO{Name: &newName}

		repo.On("FindByUUID", uuid).Return(originalUser, nil).Once()
		repo.On("Update", mock.AnythingOfType("domain.User")).Return(errors.New("db error")).Once()

		err := service.Update(context.Background(), selfActor, uuid, dto)

		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		repo.AssertExpectations(t)
	})

	t.Run("admin is allowed", func(t *testing.T) {
		name := "New Name"
		dto := domain.UserUpdateDTO{Name: &name}
		repo.On("FindByUUID", uuid).Return(&domain.User{UUID: uuid}, nil).Once()
		repo.On("Update", mock.AnythingOfType("domain.User")).Return(nil).Once()

		err := service.Update(context.Background(), adminActor, uuid, dto)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("other user is forbidden", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))
		name := "New Name"
		dto := domain.UserUpdateDTO{Name: &name}

		err := service.Update(context.Background(), otherActor, uuid, dto)

		var forbiddenErr *domain.ForbiddenError
		assert.True(t, errors.As(err, &forbiddenErr))
		repo.AssertNotCalled(t, "FindByUUID", uuid)
		repo.AssertNotCalled(t, "Update", mock.Anything)
	})
}

func TestUsersService_Delete(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))
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
		service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))

		err := service.Delete(context.Background(), otherActor, uuid)

		var forbiddenErr *domain.ForbiddenError
		assert.True(t, errors.As(err, &forbiddenErr))
		repo.AssertNotCalled(t, "Delete", uuid)
	})
}

func newVerificationUsersService() (domain.UsersService, *mocks.UsersRepositoryMock, *mocks.EmailVerificationServiceMock) {
	repo := new(mocks.UsersRepositoryMock)
	emailVerification := new(mocks.EmailVerificationServiceMock)
	return services.NewUserService(repo, emailVerification), repo, emailVerification
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

func TestUsersService_SetRefreshJTI(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))
	jti := "jti"

	t.Run("success", func(t *testing.T) {
		repo.On("SetRefreshJTI", "user-uuid", &jti).Return(nil).Once()

		err := service.SetRefreshJTI(context.Background(), "user-uuid", &jti)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		repoErr := errors.New("db error")
		repo.On("SetRefreshJTI", "user-uuid", (*string)(nil)).Return(repoErr).Once()

		err := service.SetRefreshJTI(context.Background(), "user-uuid", nil)

		assert.ErrorIs(t, err, repoErr)
	})
}

func TestUsersService_RotateRefreshJTI(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))

	t.Run("success", func(t *testing.T) {
		repo.On("RotateRefreshJTI", "user-uuid", "current", "next").Return(nil).Once()

		err := service.RotateRefreshJTI(context.Background(), "user-uuid", "current", "next")

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		repoErr := domain.NewNotFoundError("users.refreshSession.notFound")
		repo.On("RotateRefreshJTI", "user-uuid", "stale", "next").Return(repoErr).Once()

		err := service.RotateRefreshJTI(context.Background(), "user-uuid", "stale", "next")

		assert.ErrorIs(t, err, repoErr)
	})
}

func TestUsersService_CreateOAuth_EmailVerified(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, new(mocks.EmailVerificationServiceMock))

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
