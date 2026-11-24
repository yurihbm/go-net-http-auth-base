package services_test

import (
	"context"
	"errors"
	"strings"
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
	service := services.NewUserService(repo, newTransactorMock(), testClock)
	assert.NotNil(t, service)
}

func TestUsersService_GetByUUID(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, newTransactorMock(), testClock)

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
		service := services.NewUserService(repo, newTransactorMock(), testClock)

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
	service := services.NewUserService(repo, newTransactorMock(), testClock)

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

func TestUsersService_PromoteToAdmin(t *testing.T) {
	notFoundErr := domain.NewNotFoundError("users.notFound")

	t.Run("success", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		user := &domain.User{UUID: "some-uuid", Email: "test@example.com", Role: domain.RoleUser}
		promoted := &domain.User{UUID: "some-uuid", Email: "test@example.com", Role: domain.RoleAdmin}
		repo.On("FindByEmail", "test@example.com").Return(user, nil).Once()
		repo.On("UpdateRole", "some-uuid", domain.RoleAdmin).Return(promoted, nil).Once()

		result, changed, err := service.PromoteToAdmin(context.Background(), "  Test@Example.com ")

		require.NoError(t, err)
		assert.True(t, changed)
		assert.Equal(t, promoted, result)
		repo.AssertExpectations(t)
	})

	t.Run("success - already admin", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		admin := &domain.User{UUID: "some-uuid", Email: "test@example.com", Role: domain.RoleAdmin}
		repo.On("FindByEmail", "test@example.com").Return(admin, nil).Once()

		result, changed, err := service.PromoteToAdmin(context.Background(), "test@example.com")

		require.NoError(t, err)
		assert.False(t, changed)
		assert.Equal(t, admin, result)
		repo.AssertNotCalled(t, "UpdateRole", mock.Anything, mock.Anything)
	})

	t.Run("error - user not found", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("FindByEmail", "ghost@example.com").Return(nil, notFoundErr).Once()

		result, changed, err := service.PromoteToAdmin(context.Background(), "ghost@example.com")

		assert.Equal(t, notFoundErr, err)
		assert.False(t, changed)
		assert.Nil(t, result)
		repo.AssertNotCalled(t, "UpdateRole", mock.Anything, mock.Anything)
	})

	t.Run("error - update fails", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		user := &domain.User{UUID: "some-uuid", Email: "test@example.com", Role: domain.RoleUser}
		updateErr := errors.New("update failed")
		repo.On("FindByEmail", "test@example.com").Return(user, nil).Once()
		repo.On("UpdateRole", "some-uuid", domain.RoleAdmin).Return(nil, updateErr).Once()

		result, changed, err := service.PromoteToAdmin(context.Background(), "test@example.com")

		assert.Equal(t, updateErr, err)
		assert.False(t, changed)
		assert.Nil(t, result)
	})
}

func TestUsersService_Create(t *testing.T) {
	dto := domain.NewUserDTO{
		Name:         "Test User",
		Email:        " Test@Example.com",
		PasswordHash: "hashed-password",
	}
	created := &domain.User{
		UUID:         "generated-uuid",
		Name:         "Test User",
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		Role:         domain.RoleUser,
		CreatedAt:    1234567890,
	}

	t.Run("success stores the given hash without sending email", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		sender := new(mocks.EmailVerificationServiceMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("IsEmailReserved", "test@example.com").Return(false, nil).Once()
		repo.On("Create", domain.User{
			Name:         "Test User",
			Email:        "test@example.com",
			PasswordHash: "hashed-password",
			Role:         domain.RoleUser,
		}).Return(created, nil).Once()

		user, err := service.Create(context.Background(), dto)

		assert.NoError(t, err)
		assert.Equal(t, created, user)
		repo.AssertExpectations(t)
		assert.Empty(t, sender.Calls)
	})

	t.Run("success oauth (no password)", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		sender := new(mocks.EmailVerificationServiceMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		dto := domain.CreateOAuthUserDTO{
			Name:  "Test User",
			Email: "test@example.com",
		}

		repo.On("IsEmailReserved", mock.Anything).Return(false, nil).Maybe()
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
		assert.Empty(t, sender.Calls)
	})

	t.Run("repository create error", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("IsEmailReserved", mock.Anything).Return(false, nil).Maybe()
		repo.On("Create", mock.AnythingOfType("domain.User")).Return(nil, errors.New("db error")).Once()

		user, err := service.Create(context.Background(), dto)

		assert.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		assert.Nil(t, user)
		repo.AssertExpectations(t)
	})

	t.Run("error - email reserved during another user's change lock", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("Create", mock.Anything).Return(&domain.User{UUID: "squatter-uuid", Email: "taken@example.com"}, nil).Once()
		repo.On("IsEmailReserved", "taken@example.com").Return(true, nil).Once()

		user, err := service.Create(context.Background(), domain.NewUserDTO{Name: "Squatter", Email: " Taken@Example.com ", PasswordHash: "hash"})

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())
		assert.Nil(t, user)
		repo.AssertCalled(t, "Create", mock.Anything)
	})

	t.Run("error - reservation lookup fails", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		lookupErr := errors.New("db error")
		repo.On("Create", mock.Anything).Return(&domain.User{UUID: "squatter-uuid"}, nil).Once()
		repo.On("IsEmailReserved", "taken@example.com").Return(false, lookupErr).Once()

		_, err := service.Create(context.Background(), domain.NewUserDTO{Name: "Squatter", Email: "taken@example.com", PasswordHash: "hash"})

		assert.ErrorIs(t, err, lookupErr)
	})
}

func TestUsersService_Update(t *testing.T) {
	repo := new(mocks.UsersRepositoryMock)
	service := services.NewUserService(repo, newTransactorMock(), testClock)
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
		service := services.NewUserService(repo, newTransactorMock(), testClock)
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
	service := services.NewUserService(repo, newTransactorMock(), testClock)
	uuid := "some-uuid"

	t.Run("success", func(t *testing.T) {
		repo.On("FindByUUID", uuid).Return(&domain.User{UUID: uuid}, nil).Once()
		repo.On("Delete", uuid).Return(nil).Once()

		err := service.Delete(context.Background(), selfActor, uuid)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("delete fails", func(t *testing.T) {
		repo.On("FindByUUID", uuid).Return(&domain.User{UUID: uuid}, nil).Once()
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

	t.Run("error - self deletion is blocked during the email change lock", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("FindByUUID", uuid).Return(&domain.User{UUID: uuid, EmailChangedAt: testNow.Add(-time.Hour).Unix()}, nil).Once()

		err := service.Delete(context.Background(), selfActor, uuid)

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.emailChange.locked", conflictErr.Error())
		repo.AssertNotCalled(t, "Delete", uuid)
	})

	t.Run("error - self deletion is blocked one second before the email change lock ends", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("FindByUUID", uuid).Return(&domain.User{UUID: uuid, EmailChangedAt: testNow.Add(-domain.EmailChangeLock + time.Second).Unix()}, nil).Once()

		err := service.Delete(context.Background(), selfActor, uuid)

		var conflictErr *domain.ConflictError
		require.ErrorAs(t, err, &conflictErr)
		repo.AssertNotCalled(t, "Delete", uuid)
	})

	t.Run("success - self deletion is allowed when the email change lock ends", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("FindByUUID", uuid).Return(&domain.User{UUID: uuid, EmailChangedAt: testNow.Add(-domain.EmailChangeLock).Unix()}, nil).Once()
		repo.On("Delete", uuid).Return(nil).Once()

		err := service.Delete(context.Background(), selfActor, uuid)

		assert.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("admin deleting another locked user is allowed", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("Delete", uuid).Return(nil).Once()

		err := service.Delete(context.Background(), adminActor, uuid)

		assert.NoError(t, err)
		repo.AssertNotCalled(t, "FindByUUID", mock.Anything)
	})

	t.Run("error - lookup fails", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		lookupErr := errors.New("db error")
		repo.On("FindByUUID", uuid).Return(nil, lookupErr).Once()

		err := service.Delete(context.Background(), selfActor, uuid)

		assert.ErrorIs(t, err, lookupErr)
		repo.AssertNotCalled(t, "Delete", uuid)
	})

	t.Run("other user is forbidden", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)

		err := service.Delete(context.Background(), otherActor, uuid)

		var forbiddenErr *domain.ForbiddenError
		assert.True(t, errors.As(err, &forbiddenErr))
		repo.AssertNotCalled(t, "Delete", uuid)
	})
}

func TestUsersService_CreateOAuth(t *testing.T) {
	nameCases := []struct {
		name, inName, email, want string
	}{
		{"keeps a valid name", "Ana Maria", "ana@example.com", "Ana Maria"},
		{"trims spaces", "  Ana  ", "ana@example.com", "Ana"},
		{"truncates to 100 characters", strings.Repeat("é", 120), "ana@example.com", strings.Repeat("é", 100)},
		{"empty name falls back to the email local part", "", "ana.silva@example.com", "ana.silva"},
		{"short name falls back to the email local part", " Al ", "Ana.Silva@Example.com", "ana.silva"},
		{"short local part falls back to the full email", "", "al@example.com", "al@example.com"},
		{"long local part is truncated to 100 characters", "", strings.Repeat("a", 120) + "@example.com", strings.Repeat("a", 100)},
	}
	for _, tc := range nameCases {
		t.Run("success - "+tc.name, func(t *testing.T) {
			repo := new(mocks.UsersRepositoryMock)
			service := services.NewUserService(repo, newTransactorMock(), testClock)
			repo.On("IsEmailReserved", mock.Anything).Return(false, nil).Maybe()
			repo.On("Create", mock.MatchedBy(func(u domain.User) bool {
				return u.Name == tc.want
			})).Return(&domain.User{UUID: "generated-uuid"}, nil).Once()

			_, err := service.CreateOAuth(context.Background(), domain.CreateOAuthUserDTO{Name: tc.inName, Email: tc.email})

			assert.NoError(t, err)
			repo.AssertExpectations(t)
		})
	}

	t.Run("error - email reserved during another user's change lock", func(t *testing.T) {
		repo := new(mocks.UsersRepositoryMock)
		service := services.NewUserService(repo, newTransactorMock(), testClock)
		repo.On("Create", mock.Anything).Return(&domain.User{UUID: "squatter-uuid"}, nil).Once()
		repo.On("IsEmailReserved", "taken@example.com").Return(true, nil).Once()

		user, err := service.CreateOAuth(context.Background(), domain.CreateOAuthUserDTO{Name: "Squatter", Email: "Taken@example.com"})

		var conflictErr *domain.ConflictError
		require.True(t, errors.As(err, &conflictErr))
		assert.Equal(t, "users.email.conflict", conflictErr.Error())
		assert.Nil(t, user)
		repo.AssertCalled(t, "Create", mock.Anything)
	})
}
