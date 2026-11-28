package services_test

import (
	"context"
	"errors"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFeatureFlagsService(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		assert.NotNil(t, services.NewFeatureFlagsService(new(mocks.FeatureFlagsRepositoryMock)))
	})
}

func TestFeatureFlagsService_Create(t *testing.T) {
	dto := domain.CreateFeatureFlagDTO{Key: "new-dashboard", Description: "Redesigned dashboard", EnabledGlobally: true}
	entity := domain.FeatureFlag{Key: "new-dashboard", Description: "Redesigned dashboard", EnabledGlobally: true}

	t.Run("success", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		created := &domain.FeatureFlag{UUID: "flag-1", Key: "new-dashboard", Description: "Redesigned dashboard", EnabledGlobally: true}
		repo.On("Create", entity).Return(created, nil)
		service := services.NewFeatureFlagsService(repo)

		flag, err := service.Create(context.Background(), dto)

		require.NoError(t, err)
		assert.Equal(t, created, flag)
		repo.AssertExpectations(t)
	})

	t.Run("error - key conflict", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		conflict := domain.NewConflictError("featureFlags.key.conflict")
		repo.On("Create", entity).Return(nil, conflict)
		service := services.NewFeatureFlagsService(repo)

		flag, err := service.Create(context.Background(), dto)

		assert.Nil(t, flag)
		assert.Equal(t, conflict, err)
		repo.AssertExpectations(t)
	})
}

func TestFeatureFlagsService_GetByUUID(t *testing.T) {
	t.Run("success - includes the allow-list", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		stored := &domain.FeatureFlagDetails{
			UUID:      "flag-1",
			Key:       "beta",
			UserUUIDs: []string{"user-1", "user-2"},
		}
		repo.On("FindDetailsByUUID", "flag-1").Return(stored, nil)
		service := services.NewFeatureFlagsService(repo)

		details, err := service.GetByUUID(context.Background(), "flag-1")

		require.NoError(t, err)
		assert.Equal(t, stored, details)
		repo.AssertExpectations(t)
	})

	t.Run("error - flag not found", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		notFound := domain.NewNotFoundError("featureFlags.notFound")
		repo.On("FindDetailsByUUID", "flag-1").Return(nil, notFound)
		service := services.NewFeatureFlagsService(repo)

		details, err := service.GetByUUID(context.Background(), "flag-1")

		assert.Nil(t, details)
		assert.Equal(t, notFound, err)
		repo.AssertExpectations(t)
	})
}

func TestFeatureFlagsService_Update(t *testing.T) {
	enabled := true
	dto := domain.UpdateFeatureFlagDTO{EnabledGlobally: &enabled}

	t.Run("success", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		updated := &domain.FeatureFlag{UUID: "flag-1", EnabledGlobally: true}
		repo.On("Update", "flag-1", dto).Return(updated, nil)
		service := services.NewFeatureFlagsService(repo)

		flag, err := service.Update(context.Background(), "flag-1", dto)

		require.NoError(t, err)
		assert.Equal(t, updated, flag)
		repo.AssertExpectations(t)
	})

	t.Run("error - flag not found", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		notFound := domain.NewNotFoundError("featureFlags.notFound")
		repo.On("Update", "flag-1", dto).Return(nil, notFound)
		service := services.NewFeatureFlagsService(repo)

		flag, err := service.Update(context.Background(), "flag-1", dto)

		assert.Nil(t, flag)
		assert.Equal(t, notFound, err)
		repo.AssertExpectations(t)
	})
}

func TestFeatureFlagsService_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		repo.On("Delete", "flag-1").Return(nil)
		service := services.NewFeatureFlagsService(repo)

		err := service.Delete(context.Background(), "flag-1")

		require.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("error - flag not found", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		notFound := domain.NewNotFoundError("featureFlags.notFound")
		repo.On("Delete", "flag-1").Return(notFound)
		service := services.NewFeatureFlagsService(repo)

		err := service.Delete(context.Background(), "flag-1")

		assert.Equal(t, notFound, err)
		repo.AssertExpectations(t)
	})
}

func TestFeatureFlagsService_List(t *testing.T) {
	makeFlag := func(id string) domain.FeatureFlag { return domain.FeatureFlag{UUID: id, Key: "key-" + id} }
	dto := domain.ListFeatureFlagsDTO{Limit: 2}
	probeDTO := domain.ListFeatureFlagsDTO{Limit: 3}

	t.Run("success - no results, NextCursor is nil", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		repo.On("List", probeDTO).Return([]domain.FeatureFlag{}, int64(0), nil)
		service := services.NewFeatureFlagsService(repo)

		page, err := service.List(context.Background(), dto)

		require.NoError(t, err)
		assert.Empty(t, page.Items)
		assert.Nil(t, page.NextCursor)
		assert.Equal(t, int64(0), page.Total)
		repo.AssertExpectations(t)
	})

	t.Run("success - more rows than limit, items trimmed and NextCursor is last kept UUID", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		repo.On("List", probeDTO).Return([]domain.FeatureFlag{makeFlag("uuid-1"), makeFlag("uuid-2"), makeFlag("uuid-3")}, int64(5), nil)
		service := services.NewFeatureFlagsService(repo)

		page, err := service.List(context.Background(), dto)

		require.NoError(t, err)
		require.Len(t, page.Items, 2)
		assert.Equal(t, "uuid-2", page.Items[1].UUID)
		require.NotNil(t, page.NextCursor)
		assert.Equal(t, "uuid-2", *page.NextCursor)
		assert.Equal(t, int64(5), page.Total)
		repo.AssertExpectations(t)
	})

	t.Run("error - repository failure", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		failure := errors.New("boom")
		repo.On("List", probeDTO).Return(nil, int64(0), failure)
		service := services.NewFeatureFlagsService(repo)

		page, err := service.List(context.Background(), dto)

		assert.Nil(t, page)
		assert.Equal(t, failure, err)
		repo.AssertExpectations(t)
	})
}

func TestFeatureFlagsService_AddUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		repo.On("AddUser", "flag-1", "user-1").Return(nil)
		service := services.NewFeatureFlagsService(repo)

		err := service.AddUser(context.Background(), "flag-1", "user-1")

		require.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("error - user not found", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		notFound := domain.NewNotFoundError("users.notFound")
		repo.On("AddUser", "flag-1", "user-1").Return(notFound)
		service := services.NewFeatureFlagsService(repo)

		err := service.AddUser(context.Background(), "flag-1", "user-1")

		assert.Equal(t, notFound, err)
		repo.AssertExpectations(t)
	})
}

func TestFeatureFlagsService_RemoveUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		repo.On("RemoveUser", "flag-1", "user-1").Return(nil)
		service := services.NewFeatureFlagsService(repo)

		err := service.RemoveUser(context.Background(), "flag-1", "user-1")

		require.NoError(t, err)
		repo.AssertExpectations(t)
	})

	t.Run("error - user not in the allow-list", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		notFound := domain.NewNotFoundError("featureFlags.users.notFound")
		repo.On("RemoveUser", "flag-1", "user-1").Return(notFound)
		service := services.NewFeatureFlagsService(repo)

		err := service.RemoveUser(context.Background(), "flag-1", "user-1")

		assert.Equal(t, notFound, err)
		repo.AssertExpectations(t)
	})
}

func TestFeatureFlagsService_ListEnabledKeys(t *testing.T) {
	t.Run("success - signed in user", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		userUUID := "user-1"
		repo.On("ListEnabledKeys", &userUUID).Return([]string{"alpha", "beta"}, nil)
		service := services.NewFeatureFlagsService(repo)

		keys, err := service.ListEnabledKeys(context.Background(), "user-1")

		require.NoError(t, err)
		assert.Equal(t, []string{"alpha", "beta"}, keys)
		repo.AssertExpectations(t)
	})

	t.Run("success - anonymous caller is resolved without a user", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		repo.On("ListEnabledKeys", (*string)(nil)).Return([]string{"alpha"}, nil)
		service := services.NewFeatureFlagsService(repo)

		keys, err := service.ListEnabledKeys(context.Background(), "")

		require.NoError(t, err)
		assert.Equal(t, []string{"alpha"}, keys)
		repo.AssertExpectations(t)
	})

	t.Run("success - no enabled flags returns an empty list", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		repo.On("ListEnabledKeys", (*string)(nil)).Return(nil, nil)
		service := services.NewFeatureFlagsService(repo)

		keys, err := service.ListEnabledKeys(context.Background(), "")

		require.NoError(t, err)
		assert.NotNil(t, keys)
		assert.Empty(t, keys)
	})

	t.Run("error - repository failure", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		failure := errors.New("boom")
		repo.On("ListEnabledKeys", (*string)(nil)).Return(nil, failure)
		service := services.NewFeatureFlagsService(repo)

		keys, err := service.ListEnabledKeys(context.Background(), "")

		assert.Nil(t, keys)
		assert.Equal(t, failure, err)
	})
}

func TestFeatureFlagsService_IsEnabled(t *testing.T) {
	t.Run("success - key is enabled for the user", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		userUUID := "user-1"
		repo.On("ListEnabledKeys", &userUUID).Return([]string{"alpha", "beta"}, nil)
		service := services.NewFeatureFlagsService(repo)

		enabled, err := service.IsEnabled(context.Background(), "beta", "user-1")

		require.NoError(t, err)
		assert.True(t, enabled)
	})

	t.Run("success - key is not enabled, or does not exist", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		userUUID := "user-1"
		repo.On("ListEnabledKeys", &userUUID).Return([]string{"alpha"}, nil)
		service := services.NewFeatureFlagsService(repo)

		enabled, err := service.IsEnabled(context.Background(), "unknown", "user-1")

		require.NoError(t, err)
		assert.False(t, enabled)
	})

	t.Run("error - repository failure", func(t *testing.T) {
		repo := new(mocks.FeatureFlagsRepositoryMock)
		failure := errors.New("boom")
		repo.On("ListEnabledKeys", (*string)(nil)).Return(nil, failure)
		service := services.NewFeatureFlagsService(repo)

		enabled, err := service.IsEnabled(context.Background(), "alpha", "")

		assert.False(t, enabled)
		assert.Equal(t, failure, err)
	})
}
