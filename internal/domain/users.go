package domain

import (
	"context"
	"time"
)

type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
)

func (r UserRole) IsValid() bool {
	switch r {
	case RoleAdmin, RoleUser:
		return true
	default:
		return false
	}
}

type User struct {
	UUID                      string   `json:"uuid"`
	Name                      string   `json:"name"`
	Email                     string   `json:"email"`
	PasswordHash              string   `json:"-"`
	Role                      UserRole `json:"role"`
	EmailVerified             bool     `json:"email_verified"`
	EmailVersion              int      `json:"-"`
	EmailChangedAt            int64    `json:"-"`
	StepUpFailures            int      `json:"-"`
	StepUpFailuresWindowStart int64    `json:"-"`
	CreatedAt                 int64    `json:"created_at"`
	UpdatedAt                 int64    `json:"updated_at"`
}

type CreateUserDTO struct {
	Name     string `json:"name"     validate:"required"`
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type CreateOAuthUserDTO struct {
	Name          string
	Email         string
	EmailVerified bool
}

type UserUpdateDTO struct {
	Name *string `json:"name,omitempty"`
}

type RequestEmailChangeDTO struct {
	Email string `json:"email" validate:"required,email"`
}

type ConfirmEmailChangeDTO struct {
	Token string `json:"token" validate:"required"`
}

type Actor struct {
	UUID string
	Role UserRole
}

func (a Actor) CanAccess(userUUID string) bool {
	return a.Role == RoleAdmin || (a.UUID != "" && a.UUID == userUUID)
}

type UsersService interface {
	GetByUUID(context.Context, Actor, string) (*User, error)
	GetByEmail(context.Context, string) (*User, error)
	Create(context.Context, CreateUserDTO) (*User, error)
	CreateOAuth(context.Context, CreateOAuthUserDTO) (*User, error)
	Update(context.Context, Actor, string, UserUpdateDTO) (*User, error)
	VerifyEmail(context.Context, string) error
	ResendVerification(context.Context, string) error
	RequestEmailChange(context.Context, Actor, string) error
	ConfirmEmailChange(context.Context, string) (*User, error)
	Delete(context.Context, Actor, string) error
}

type UsersRepository interface {
	FindByUUID(context.Context, string) (*User, error)
	FindByEmail(context.Context, string) (*User, error)
	Create(context.Context, User) (*User, error)
	Update(context.Context, User) (*User, error)
	UpdateEmail(ctx context.Context, uuid string, email string, expectedVersion int, changedAt *time.Time) (*User, error)
	RecordStepUpFailure(ctx context.Context, uuid string, window time.Duration) (int, error)
	MarkEmailVerified(context.Context, string) error
	Delete(context.Context, string) error
}
