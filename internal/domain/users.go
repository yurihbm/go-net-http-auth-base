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
	Password string `json:"password" validate:"required,min=8,max=72"`
}

type NewUserDTO struct {
	Name         string
	Email        string
	PasswordHash string
}

type CreateOAuthUserDTO struct {
	Name  string
	Email string
}

type UserUpdateDTO struct {
	Name *string `json:"name,omitempty"`
}

type RequestEmailChangeDTO struct {
	Email string `json:"email" validate:"required,email"`
}

type RevertEmailChangeDTO struct {
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
	PromoteToAdmin(ctx context.Context, email string) (user *User, changed bool, err error)
	Create(context.Context, NewUserDTO) (*User, error)
	CreateOAuth(context.Context, CreateOAuthUserDTO) (*User, error)
	Update(context.Context, Actor, string, UserUpdateDTO) (*User, error)
	Delete(context.Context, Actor, string) error
}

type UsersRepository interface {
	FindByUUID(context.Context, string) (*User, error)
	FindByEmail(context.Context, string) (*User, error)
	Create(context.Context, User) (*User, error)
	Update(context.Context, User) (*User, error)
	UpdateEmail(ctx context.Context, uuid string, email string, expectedVersion int, changedAt *time.Time) (*User, error)
	UpdateRole(ctx context.Context, uuid string, role UserRole) (*User, error)
	ReserveStepUpGuess(ctx context.Context, uuid string, window time.Duration) error
	RefundStepUpGuess(ctx context.Context, uuid string) error
	IsEmailReserved(ctx context.Context, email string) (bool, error)
	Delete(context.Context, string) error
}
