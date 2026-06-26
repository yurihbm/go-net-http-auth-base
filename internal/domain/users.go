package domain

import "context"

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
	UUID         string   `json:"uuid"`
	Name         string   `json:"name"`
	Email        string   `json:"email"`
	PasswordHash string   `json:"-"`
	Role         UserRole `json:"role"`
	CreatedAt    int64    `json:"created_at"`
	UpdatedAt    int64    `json:"updated_at"`
}

type CreateUserDTO struct {
	Name     string `json:"name"     validate:"required"`
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type CreateOAuthUserDTO struct {
	Name  string
	Email string
}

type UserUpdateDTO struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty" validate:"omitempty,email"`
}

type UsersService interface {
	GetByUUID(context.Context, string) (*User, error)
	GetByEmail(context.Context, string) (*User, error)
	Create(context.Context, CreateUserDTO) (*User, error)
	CreateOAuth(context.Context, CreateOAuthUserDTO) (*User, error)
	Update(context.Context, string, UserUpdateDTO) error
	Delete(context.Context, string) error
}

type UsersRepository interface {
	FindByUUID(context.Context, string) (*User, error)
	FindByEmail(context.Context, string) (*User, error)
	Create(context.Context, User) (*User, error)
	Update(context.Context, User) error
	Delete(context.Context, string) error
}
