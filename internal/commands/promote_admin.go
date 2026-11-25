package commands

import (
	"context"
	"errors"
	"fmt"
	"io"

	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
)

var errPromoteAdminUsage = errors.New("usage: promote-admin <email>")

func PromoteAdmin(ctx context.Context, users domain.UsersService, audit domain.AuditService, out io.Writer, args []string) error {
	if len(args) != 1 {
		return errPromoteAdminUsage
	}

	user, changed, err := users.PromoteToAdmin(ctx, args[0])
	if err != nil {
		return err
	}
	if !changed {
		_, err = fmt.Fprintf(out, "%s is already an admin\n", user.Email)
		return err
	}

	requestUUID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	err = audit.Log(ctx, domain.CreateAuditLogDTO{
		Action:       domain.AuditActionUserRoleChange,
		ResourceType: domain.AuditResourceUser,
		ResourceUUID: user.UUID,
		RequestUUID:  requestUUID.String(),
		Changes:      map[string]string{"role": string(domain.RoleAdmin)},
		Status:       domain.AuditStatusSuccess,
	})
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "promoted %s to admin\n", user.Email)
	return err
}
