package domain

import (
	"context"
	"time"
)

const (
	PasswordResetTTL         = 10 * time.Minute
	PasswordResetMaxAttempts = 5
)

var ErrPasswordResetInvalidCode = NewUnauthorizedError("auth.passwordReset.invalidCode")

type PasswordReset struct {
	UUID         string
	UserUUID     string
	Email        string
	EmailVersion int
	CodeHash     string
	Attempts     int
	ExpiresAt    int64
}

type ForgotPasswordDTO struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordDTO struct {
	Code     string `json:"code"     validate:"required,len=6,numeric"`
	Password string `json:"password" validate:"required,min=8,max=72"`
}

type ChangePasswordDTO struct {
	NewPassword string `json:"new_password" validate:"required,min=8,max=72"`
}

type PasswordResetRepository interface {
	Create(ctx context.Context, reset PasswordReset) (*PasswordReset, error)
	FindByUUID(ctx context.Context, uuid string) (*PasswordReset, error)
	Attempt(ctx context.Context, uuid string, maxAttempts int) (*PasswordReset, error)
	Consume(ctx context.Context, uuid string, codeHash string) (*PasswordReset, error)
	Delete(ctx context.Context, uuid string) error
	DeleteByUser(ctx context.Context, userUUID string) error
}

type PasswordService interface {
	RequestReset(ctx context.Context, email string) (string, error)
	ResetPassword(ctx context.Context, resetUUID string, dto ResetPasswordDTO) (*User, error)
	ChangePassword(ctx context.Context, actor Actor, sessionUUID string, dto ChangePasswordDTO) error
}
