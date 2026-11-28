package repositories_test

import (
	"context"
	"slices"
	"testing"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/repositories"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupFeatureFlagsRepoTest(t *testing.T) (domain.FeatureFlagsRepository, domain.UsersRepository) {
	if testing.Short() {
		t.Skip("Skipping repository tests in short mode.")
	}

	repo := repositories.NewFeatureFlagsPostgresRepository(testDB)
	require.NotNil(t, repo)

	truncateTables(context.Background(), testDB)

	return repo, repositories.NewUsersPostgresRepository(testDB)
}

func seedFeatureFlag(t *testing.T, repo domain.FeatureFlagsRepository, key string, enabledGlobally bool) *domain.FeatureFlag {
	t.Helper()

	flag, err := repo.Create(context.Background(), domain.FeatureFlag{
		Key:             key,
		Description:     "description of " + key,
		EnabledGlobally: enabledGlobally,
	})
	require.NoError(t, err)
	require.NotNil(t, flag)

	return flag
}

func TestNewFeatureFlagsPostgresRepository(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		assert.NotNil(t, repositories.NewFeatureFlagsPostgresRepository(nil))
	})
}

func TestFeatureFlagsPostgresRepository_Create(t *testing.T) {
	repo, _ := setupFeatureFlagsRepoTest(t)

	t.Run("success", func(t *testing.T) {
		flag, err := repo.Create(context.Background(), domain.FeatureFlag{
			Key:             "new-dashboard",
			Description:     "Redesigned dashboard",
			EnabledGlobally: true,
		})

		require.NoError(t, err)
		require.NotNil(t, flag)
		assert.NotEmpty(t, flag.UUID)
		assert.Equal(t, "new-dashboard", flag.Key)
		assert.Equal(t, "Redesigned dashboard", flag.Description)
		assert.True(t, flag.EnabledGlobally)
		assert.NotZero(t, flag.CreatedAt)
		assert.NotZero(t, flag.UpdatedAt)
	})

	t.Run("error - key conflict", func(t *testing.T) {
		seedFeatureFlag(t, repo, "duplicated", false)

		flag, err := repo.Create(context.Background(), domain.FeatureFlag{Key: "duplicated"})

		assert.Nil(t, flag)
		var conflictErr *domain.ConflictError
		require.ErrorAs(t, err, &conflictErr)
		assert.Equal(t, "featureFlags.key.conflict", conflictErr.Error())
	})
}

func TestFeatureFlagsPostgresRepository_FindDetailsByUUID(t *testing.T) {
	repo, usersRepo := setupFeatureFlagsRepoTest(t)

	t.Run("success - empty allow-list", func(t *testing.T) {
		created := seedFeatureFlag(t, repo, "find-me", false)

		details, err := repo.FindDetailsByUUID(context.Background(), created.UUID)

		require.NoError(t, err)
		assert.Equal(t, *created, details.FeatureFlag)
		assert.Equal(t, []string{}, details.UserUUIDs)
	})

	t.Run("success - includes the allow-list sorted by user uuid", func(t *testing.T) {
		created := seedFeatureFlag(t, repo, "with-users", false)
		first := seedUser(t, usersRepo)
		second, err := usersRepo.Create(context.Background(), domain.User{
			Name:         "Jane Doe",
			Email:        "jane.doe@example.com",
			PasswordHash: "hashed_password",
			Role:         domain.RoleUser,
		})
		require.NoError(t, err)
		require.NoError(t, repo.AddUser(context.Background(), created.UUID, second.UUID))
		require.NoError(t, repo.AddUser(context.Background(), created.UUID, first.UUID))

		details, err := repo.FindDetailsByUUID(context.Background(), created.UUID)

		require.NoError(t, err)
		assert.Equal(t, *created, details.FeatureFlag)
		expected := []string{first.UUID, second.UUID}
		slices.Sort(expected)
		assert.Equal(t, expected, details.UserUUIDs)
	})

	t.Run("error - not found", func(t *testing.T) {
		details, err := repo.FindDetailsByUUID(context.Background(), uuid.NewString())

		assert.Nil(t, details)
		var notFoundErr *domain.NotFoundError
		require.ErrorAs(t, err, &notFoundErr)
		assert.Equal(t, "featureFlags.notFound", notFoundErr.Error())
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		details, err := repo.FindDetailsByUUID(context.Background(), "not-a-uuid")

		assert.Nil(t, details)
		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "featureFlags.invalidFlagUUID", validationErr.Error())
	})
}

func TestFeatureFlagsPostgresRepository_Update(t *testing.T) {
	repo, _ := setupFeatureFlagsRepoTest(t)

	t.Run("success - only the provided fields change", func(t *testing.T) {
		created := seedFeatureFlag(t, repo, "update-me", false)
		description := "new description"

		flag, err := repo.Update(context.Background(), created.UUID, domain.UpdateFeatureFlagDTO{
			Description: &description,
		})

		require.NoError(t, err)
		assert.Equal(t, "new description", flag.Description)
		assert.False(t, flag.EnabledGlobally)
		assert.Equal(t, created.Key, flag.Key)
	})

	t.Run("success - enabled globally can be switched off", func(t *testing.T) {
		created := seedFeatureFlag(t, repo, "switch-off", true)
		enabled := false

		flag, err := repo.Update(context.Background(), created.UUID, domain.UpdateFeatureFlagDTO{
			EnabledGlobally: &enabled,
		})

		require.NoError(t, err)
		assert.False(t, flag.EnabledGlobally)
		assert.Equal(t, created.Description, flag.Description)
	})

	t.Run("error - not found", func(t *testing.T) {
		enabled := true

		flag, err := repo.Update(context.Background(), uuid.NewString(), domain.UpdateFeatureFlagDTO{
			EnabledGlobally: &enabled,
		})

		assert.Nil(t, flag)
		var notFoundErr *domain.NotFoundError
		require.ErrorAs(t, err, &notFoundErr)
		assert.Equal(t, "featureFlags.notFound", notFoundErr.Error())
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		flag, err := repo.Update(context.Background(), "not-a-uuid", domain.UpdateFeatureFlagDTO{})

		assert.Nil(t, flag)
		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "featureFlags.invalidFlagUUID", validationErr.Error())
	})
}

func TestFeatureFlagsPostgresRepository_Delete(t *testing.T) {
	repo, usersRepo := setupFeatureFlagsRepoTest(t)

	t.Run("success - removes the flag and its allow-list", func(t *testing.T) {
		flag := seedFeatureFlag(t, repo, "delete-me", false)
		user := seedUser(t, usersRepo)
		require.NoError(t, repo.AddUser(context.Background(), flag.UUID, user.UUID))

		err := repo.Delete(context.Background(), flag.UUID)

		require.NoError(t, err)
		_, err = repo.FindDetailsByUUID(context.Background(), flag.UUID)
		assert.Error(t, err)
		keys, err := repo.ListEnabledKeys(context.Background(), &user.UUID)
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("error - not found", func(t *testing.T) {
		err := repo.Delete(context.Background(), uuid.NewString())

		var notFoundErr *domain.NotFoundError
		require.ErrorAs(t, err, &notFoundErr)
		assert.Equal(t, "featureFlags.notFound", notFoundErr.Error())
	})

	t.Run("error - invalid uuid", func(t *testing.T) {
		err := repo.Delete(context.Background(), "not-a-uuid")

		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "featureFlags.invalidFlagUUID", validationErr.Error())
	})
}

func TestFeatureFlagsPostgresRepository_List(t *testing.T) {
	repo, _ := setupFeatureFlagsRepoTest(t)

	first := seedFeatureFlag(t, repo, "flag-a", false)
	second := seedFeatureFlag(t, repo, "flag-b", false)
	third := seedFeatureFlag(t, repo, "flag-c", true)

	t.Run("success - newest first with the total", func(t *testing.T) {
		flags, total, err := repo.List(context.Background(), domain.ListFeatureFlagsDTO{Limit: 2})

		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		require.Len(t, flags, 2)
		assert.Equal(t, third.UUID, flags[0].UUID)
		assert.Equal(t, second.UUID, flags[1].UUID)
	})

	t.Run("success - cursor continues after the given flag", func(t *testing.T) {
		cursor := second.UUID

		flags, total, err := repo.List(context.Background(), domain.ListFeatureFlagsDTO{Cursor: &cursor, Limit: 10})

		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		require.Len(t, flags, 1)
		assert.Equal(t, first.UUID, flags[0].UUID)
	})

	t.Run("error - invalid cursor", func(t *testing.T) {
		cursor := "not-a-uuid"

		flags, total, err := repo.List(context.Background(), domain.ListFeatureFlagsDTO{Cursor: &cursor, Limit: 10})

		assert.Nil(t, flags)
		assert.Zero(t, total)
		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "featureFlags.invalidCursor", validationErr.Error())
	})
}

func TestFeatureFlagsPostgresRepository_AddUser(t *testing.T) {
	repo, usersRepo := setupFeatureFlagsRepoTest(t)
	user := seedUser(t, usersRepo)

	t.Run("success - adding twice keeps one row", func(t *testing.T) {
		flag := seedFeatureFlag(t, repo, "beta", false)

		require.NoError(t, repo.AddUser(context.Background(), flag.UUID, user.UUID))
		require.NoError(t, repo.AddUser(context.Background(), flag.UUID, user.UUID))

		details, err := repo.FindDetailsByUUID(context.Background(), flag.UUID)
		require.NoError(t, err)
		assert.Equal(t, []string{user.UUID}, details.UserUUIDs)
	})

	t.Run("error - flag not found", func(t *testing.T) {
		err := repo.AddUser(context.Background(), uuid.NewString(), user.UUID)

		var notFoundErr *domain.NotFoundError
		require.ErrorAs(t, err, &notFoundErr)
		assert.Equal(t, "featureFlags.notFound", notFoundErr.Error())
	})

	t.Run("error - user not found", func(t *testing.T) {
		flag := seedFeatureFlag(t, repo, "no-such-user", false)

		err := repo.AddUser(context.Background(), flag.UUID, uuid.NewString())

		var notFoundErr *domain.NotFoundError
		require.ErrorAs(t, err, &notFoundErr)
		assert.Equal(t, "users.notFound", notFoundErr.Error())
	})

	t.Run("error - invalid flag uuid", func(t *testing.T) {
		err := repo.AddUser(context.Background(), "not-a-uuid", user.UUID)

		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "featureFlags.invalidFlagUUID", validationErr.Error())
	})

	t.Run("error - invalid user uuid", func(t *testing.T) {
		flag := seedFeatureFlag(t, repo, "invalid-user", false)

		err := repo.AddUser(context.Background(), flag.UUID, "not-a-uuid")

		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "users.invalidUserUUID", validationErr.Error())
	})
}

func TestFeatureFlagsPostgresRepository_RemoveUser(t *testing.T) {
	repo, usersRepo := setupFeatureFlagsRepoTest(t)
	user := seedUser(t, usersRepo)

	t.Run("success", func(t *testing.T) {
		flag := seedFeatureFlag(t, repo, "remove-user", false)
		require.NoError(t, repo.AddUser(context.Background(), flag.UUID, user.UUID))

		err := repo.RemoveUser(context.Background(), flag.UUID, user.UUID)

		require.NoError(t, err)
		details, err := repo.FindDetailsByUUID(context.Background(), flag.UUID)
		require.NoError(t, err)
		assert.Empty(t, details.UserUUIDs)
	})

	t.Run("error - user not in the allow-list", func(t *testing.T) {
		flag := seedFeatureFlag(t, repo, "not-listed", false)

		err := repo.RemoveUser(context.Background(), flag.UUID, user.UUID)

		var notFoundErr *domain.NotFoundError
		require.ErrorAs(t, err, &notFoundErr)
		assert.Equal(t, "featureFlags.users.notFound", notFoundErr.Error())
	})

	t.Run("error - invalid flag uuid", func(t *testing.T) {
		err := repo.RemoveUser(context.Background(), "not-a-uuid", user.UUID)

		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "featureFlags.invalidFlagUUID", validationErr.Error())
	})

	t.Run("error - invalid user uuid", func(t *testing.T) {
		err := repo.RemoveUser(context.Background(), uuid.NewString(), "not-a-uuid")

		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "users.invalidUserUUID", validationErr.Error())
	})
}

func TestFeatureFlagsPostgresRepository_ListEnabledKeys(t *testing.T) {
	repo, usersRepo := setupFeatureFlagsRepoTest(t)

	listed := seedUser(t, usersRepo)
	other, err := usersRepo.Create(context.Background(), domain.User{
		Name:         "Jane Doe",
		Email:        "jane.doe@example.com",
		PasswordHash: "hashed_password",
		Role:         domain.RoleUser,
	})
	require.NoError(t, err)

	seedFeatureFlag(t, repo, "zeta-global", true)
	seedFeatureFlag(t, repo, "off-for-everyone", false)
	beta := seedFeatureFlag(t, repo, "alpha-beta", false)
	require.NoError(t, repo.AddUser(context.Background(), beta.UUID, listed.UUID))

	t.Run("success - anonymous sees only the global flags", func(t *testing.T) {
		keys, err := repo.ListEnabledKeys(context.Background(), nil)

		require.NoError(t, err)
		assert.Equal(t, []string{"zeta-global"}, keys)
	})

	t.Run("success - allow-listed user sees global and own flags sorted by key", func(t *testing.T) {
		keys, err := repo.ListEnabledKeys(context.Background(), &listed.UUID)

		require.NoError(t, err)
		assert.Equal(t, []string{"alpha-beta", "zeta-global"}, keys)
	})

	t.Run("success - other user does not see the allow-listed flag", func(t *testing.T) {
		keys, err := repo.ListEnabledKeys(context.Background(), &other.UUID)

		require.NoError(t, err)
		assert.Equal(t, []string{"zeta-global"}, keys)
	})

	t.Run("error - invalid user uuid", func(t *testing.T) {
		invalid := "not-a-uuid"

		keys, err := repo.ListEnabledKeys(context.Background(), &invalid)

		assert.Nil(t, keys)
		var validationErr *domain.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "users.invalidUserUUID", validationErr.Error())
	})
}
