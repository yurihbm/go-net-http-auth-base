package commands_test

import (
	"bytes"
	"context"
	"testing"

	"go-net-http-auth-base/internal/commands"
	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPromoteAdmin(t *testing.T) {
	user := &domain.User{UUID: "user-uuid", Email: "john@example.com", Role: domain.RoleAdmin}

	t.Run("success", func(t *testing.T) {
		users := new(mocks.UsersServiceMock)
		audit := new(mocks.AuditServiceMock)
		out := new(bytes.Buffer)
		users.On("PromoteToAdmin", "john@example.com").Return(user, true, nil).Once()
		audit.On("Log", mock.MatchedBy(func(d domain.CreateAuditLogDTO) bool {
			changes, ok := d.Changes.(map[string]string)
			return d.ActorUUID == nil &&
				d.Action == domain.AuditActionUserRoleChange &&
				d.ResourceType == domain.AuditResourceUser &&
				d.ResourceUUID == "user-uuid" &&
				d.Status == domain.AuditStatusSuccess &&
				d.RequestUUID != "" &&
				ok && changes["role"] == "admin"
		})).Return(nil).Once()

		err := commands.PromoteAdmin(context.Background(), users, audit, out, []string{"john@example.com"})

		require.NoError(t, err)
		assert.Equal(t, "promoted john@example.com to admin\n", out.String())
		users.AssertExpectations(t)
		audit.AssertExpectations(t)
	})

	t.Run("success - already admin", func(t *testing.T) {
		users := new(mocks.UsersServiceMock)
		audit := new(mocks.AuditServiceMock)
		out := new(bytes.Buffer)
		users.On("PromoteToAdmin", "john@example.com").Return(user, false, nil).Once()

		err := commands.PromoteAdmin(context.Background(), users, audit, out, []string{"john@example.com"})

		require.NoError(t, err)
		assert.Equal(t, "john@example.com is already an admin\n", out.String())
		audit.AssertNotCalled(t, "Log", mock.Anything)
	})

	t.Run("error - wrong arg count", func(t *testing.T) {
		for _, args := range [][]string{nil, {"a@example.com", "b@example.com"}} {
			users := new(mocks.UsersServiceMock)
			audit := new(mocks.AuditServiceMock)

			err := commands.PromoteAdmin(context.Background(), users, audit, new(bytes.Buffer), args)

			assert.Error(t, err)
			users.AssertNotCalled(t, "PromoteToAdmin", mock.Anything)
		}
	})

	t.Run("error - user not found", func(t *testing.T) {
		users := new(mocks.UsersServiceMock)
		audit := new(mocks.AuditServiceMock)
		notFound := domain.NewNotFoundError("users.notFound")
		users.On("PromoteToAdmin", "ghost@example.com").Return(nil, false, notFound).Once()

		err := commands.PromoteAdmin(context.Background(), users, audit, new(bytes.Buffer), []string{"ghost@example.com"})

		assert.Equal(t, notFound, err)
		audit.AssertNotCalled(t, "Log", mock.Anything)
	})
}
