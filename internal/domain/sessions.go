package domain

import (
	"context"
	"time"
)

type UserSession struct {
	UUID       string `json:"uuid"`
	UserUUID   string `json:"user_uuid"`
	CurrentJTI string `json:"-"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

type SessionsRepository interface {
	Create(context.Context, UserSession) (*UserSession, error)
	FindByUUID(ctx context.Context, userUUID string, sessionUUID string) (*UserSession, error)
	RotateJTI(ctx context.Context, userUUID string, sessionUUID string, currentJTI string, nextJTI string) error
	Delete(ctx context.Context, userUUID string, sessionUUID string) error
	DeleteExpiredByUser(ctx context.Context, userUUID string, idleTimeout time.Duration) error
	DeleteOldestBeyond(ctx context.Context, userUUID string, keep int) error
}
