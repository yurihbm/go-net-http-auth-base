package services

import (
	"context"
	"time"

	"go-net-http-auth-base/internal/domain"
)

var errForbiddenUserAccess = domain.NewForbiddenError("users.forbidden")

type usersService struct {
	repo       domain.UsersRepository
	transactor domain.Transactor
}

func NewUserService(repo domain.UsersRepository, transactor domain.Transactor) domain.UsersService {
	return &usersService{repo: repo, transactor: transactor}
}

func (s *usersService) GetByUUID(ctx context.Context, actor domain.Actor, uuid string) (*domain.User, error) {
	if !actor.CanAccess(uuid) {
		return nil, errForbiddenUserAccess
	}
	return s.repo.FindByUUID(ctx, uuid)
}

func (s *usersService) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.repo.FindByEmail(ctx, normalizeEmail(email))
}

func (s *usersService) PromoteToAdmin(ctx context.Context, email string) (*domain.User, bool, error) {
	user, err := s.repo.FindByEmail(ctx, normalizeEmail(email))
	if err != nil {
		return nil, false, err
	}
	if user.Role == domain.RoleAdmin {
		return user, false, nil
	}

	promoted, err := s.repo.UpdateRole(ctx, user.UUID, domain.RoleAdmin)
	if err != nil {
		return nil, false, err
	}
	return promoted, true, nil
}

func (s *usersService) Create(ctx context.Context, dto domain.NewUserDTO) (*domain.User, error) {
	user := domain.User{
		Name:         dto.Name,
		Email:        normalizeEmail(dto.Email),
		PasswordHash: dto.PasswordHash,
		Role:         domain.RoleUser,
	}
	return s.createUnreserved(ctx, user)
}

func (s *usersService) CreateOAuth(ctx context.Context, dto domain.CreateOAuthUserDTO) (*domain.User, error) {
	user := domain.User{
		Name:  dto.Name,
		Email: normalizeEmail(dto.Email),
		Role:  domain.RoleUser,
	}
	return s.createUnreserved(ctx, user)
}

func (s *usersService) Update(ctx context.Context, actor domain.Actor, uuid string, dto domain.UserUpdateDTO) (*domain.User, error) {
	if !actor.CanAccess(uuid) {
		return nil, errForbiddenUserAccess
	}

	user, err := s.repo.FindByUUID(ctx, uuid)
	if err != nil {
		return nil, err
	}

	if dto.Name != nil {
		user.Name = *dto.Name
	}

	return s.repo.Update(ctx, *user)
}

// The reservation is checked after the write, inside its transaction: a write
// that waited on a concurrent email change only proceeds once that change is
// committed, so the check sees the reservation it created.
func (s *usersService) createUnreserved(ctx context.Context, user domain.User) (*domain.User, error) {
	var created *domain.User
	err := s.transactor.WithinTx(ctx, func(ctx context.Context) error {
		var err error
		created, err = s.repo.Create(ctx, user)
		if err != nil {
			return err
		}
		return ensureEmailNotReserved(ctx, s.repo, user.Email)
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// A recently changed email stays reserved for its previous owner during the
// lock window so the undo link can still restore it.
func ensureEmailNotReserved(ctx context.Context, repo domain.UsersRepository, email string) error {
	reserved, err := repo.IsEmailReserved(ctx, email)
	if err != nil {
		return err
	}
	if reserved {
		return domain.NewConflictError("users.email.conflict")
	}
	return nil
}

func isEmailChangeLocked(user *domain.User) bool {
	return user.EmailChangedAt != 0 && time.Now().Before(time.Unix(user.EmailChangedAt, 0).Add(domain.EmailChangeLock))
}

func (s *usersService) Delete(ctx context.Context, actor domain.Actor, uuid string) error {
	if !actor.CanAccess(uuid) {
		return errForbiddenUserAccess
	}

	if actor.UUID == uuid {
		user, err := s.repo.FindByUUID(ctx, uuid)
		if err != nil {
			return err
		}
		if isEmailChangeLocked(user) {
			return domain.NewConflictError("users.emailChange.locked")
		}
	}

	return s.repo.Delete(ctx, uuid)
}
