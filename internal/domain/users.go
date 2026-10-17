package domain

import (
	"context"
	"strings"
)

type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
)

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (r UserRole) IsValid() bool {
	switch r {
	case RoleAdmin, RoleUser:
		return true
	default:
		return false
	}
}

type User struct {
	UUID          string   `json:"uuid"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	PasswordHash  string   `json:"-"`
	Role          UserRole `json:"role"`
	EmailVerified bool     `json:"email_verified"`
	CreatedAt     int64    `json:"created_at"`
	UpdatedAt     int64    `json:"updated_at"`
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
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty" validate:"omitempty,email"`
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
	Update(context.Context, Actor, string, UserUpdateDTO) error
	VerifyEmail(context.Context, string) error
	ResendVerification(context.Context, string) error
	Delete(context.Context, Actor, string) error
}

type UsersRepository interface {
	FindByUUID(context.Context, string) (*User, error)
	FindByEmail(context.Context, string) (*User, error)
	Create(context.Context, User) (*User, error)
	Update(context.Context, User) error
	MarkEmailVerified(context.Context, string) error
	Delete(context.Context, string) error
}
