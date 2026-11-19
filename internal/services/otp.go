package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"

	"go-net-http-auth-base/internal/domain"
)

func generateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func hashOTP(key []byte, scope string, code string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(scope + ":" + code))
	return hex.EncodeToString(mac.Sum(nil))
}

// guessCode reserves a guess for the address before the attempt is counted, so
// parallel guesses never exceed the per-address cap, and gives it back unless a
// wrong code was compared.
func guessCode(ctx context.Context, limiter domain.EmailSendLimiter, email string, codeHash string, invalidCode error, attempt func() (string, error)) error {
	if err := limiter.ReserveCodeGuess(ctx, email, domain.EmailCodeFailureWindow); err != nil {
		return err
	}

	storedHash, err := attempt()
	if err != nil {
		refundCodeGuess(ctx, limiter, email)
		return err
	}

	if !hmac.Equal([]byte(storedHash), []byte(codeHash)) {
		return invalidCode
	}
	refundCodeGuess(ctx, limiter, email)
	return nil
}

func refundCodeGuess(ctx context.Context, limiter domain.EmailSendLimiter, email string) {
	if err := limiter.RefundCodeGuess(ctx, email); err != nil {
		slog.ErrorContext(ctx, "code guess refund failed", "error", err)
	}
}

func sendOrRollback(ctx context.Context, sendFailedKey string, send func() error, rollback func() error) error {
	sendErr := send()
	if sendErr == nil {
		return nil
	}
	if err := rollback(); err != nil {
		slog.ErrorContext(ctx, "code cleanup after a failed send failed", "error", err, "send_failed_key", sendFailedKey)
	}
	return domain.NewInternalServerError(sendFailedKey, sendErr)
}
