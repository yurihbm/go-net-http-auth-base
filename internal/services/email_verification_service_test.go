package services_test

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"testing"
	"time"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/internal/mocks"
	"go-net-http-auth-base/internal/services"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const verificationURL = "https://app.test/verify-email"

func TestEmailVerificationService_SendVerificationEmail(t *testing.T) {
	user := &domain.User{UUID: "user-uuid", Email: "test@example.com", Name: "Test"}

	t.Run("sends a message with a verification link", func(t *testing.T) {
		tokens := services.NewTokenService(tokenSecret)
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(tokens, emailProvider, verificationURL)
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendVerificationEmail(context.Background(), user)

		require.NoError(t, err)
		assert.Equal(t, user.Email, sent.To)
		assert.Equal(t, "Verify your email address", sent.Subject)

		link := regexp.MustCompile(`https://app\.test/verify-email\?token=[^\s"<]+`).FindString(sent.Text)
		require.NotEmpty(t, link)
		parsed, err := url.Parse(link)
		require.NoError(t, err)
		data, err := tokens.VerifyToken(context.Background(), domain.VerifyTokenDTO{
			Token:    parsed.Query().Get("token"),
			Audience: domain.TokenAudienceEmailVerification,
		})
		require.NoError(t, err)
		assert.Equal(t, user.UUID, data.Subject)
		assert.InDelta(t, time.Now().Add(24*time.Hour).Unix(), data.Expiration, 5)
		assert.Contains(t, sent.HTML, verificationURL+"?token=")
	})

	t.Run("keeps existing query params and escapes the HTML link", func(t *testing.T) {
		tokens := new(mocks.TokenServiceMock)
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(tokens, emailProvider, "https://app.test/verify?lang=en")
		tokens.On("GenerateToken", domain.GenerateTokenDTO{
			Subject:  user.UUID,
			Audience: domain.TokenAudienceEmailVerification,
		}).Return("signed-token", nil).Once()
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendVerificationEmail(context.Background(), user)

		require.NoError(t, err)
		assert.Contains(t, sent.Text, "https://app.test/verify?lang=en&token=signed-token")
		assert.Contains(t, sent.HTML, `href="https://app.test/verify?lang=en&amp;token=signed-token"`)
		tokens.AssertExpectations(t)
	})

	t.Run("returns token error", func(t *testing.T) {
		tokens := new(mocks.TokenServiceMock)
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(tokens, emailProvider, verificationURL)
		tokenErr := errors.New("sign failed")
		tokens.On("GenerateToken", mock.Anything).Return("", tokenErr).Once()

		err := service.SendVerificationEmail(context.Background(), user)

		assert.ErrorIs(t, err, tokenErr)
		emailProvider.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
	})

	t.Run("returns provider error", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(services.NewTokenService(tokenSecret), emailProvider, verificationURL)
		sendErr := errors.New("smtp down")
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(sendErr).Once()

		err := service.SendVerificationEmail(context.Background(), user)

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestEmailVerificationService_VerifyVerificationToken(t *testing.T) {
	t.Run("returns the subject of a valid token", func(t *testing.T) {
		tokens := new(mocks.TokenServiceMock)
		service := services.NewEmailVerificationService(tokens, new(mocks.EmailProviderMock), verificationURL)
		tokens.On("VerifyToken", domain.VerifyTokenDTO{
			Token:    "verification-token",
			Audience: domain.TokenAudienceEmailVerification,
		}).Return(&domain.VerifiedTokenData{Subject: "user-uuid"}, nil).Once()

		userUUID, err := service.VerifyVerificationToken(context.Background(), "verification-token")

		require.NoError(t, err)
		assert.Equal(t, "user-uuid", userUUID)
		tokens.AssertExpectations(t)
	})

	t.Run("returns the token error", func(t *testing.T) {
		tokens := new(mocks.TokenServiceMock)
		service := services.NewEmailVerificationService(tokens, new(mocks.EmailProviderMock), verificationURL)
		tokens.On("VerifyToken", mock.Anything).Return(nil, services.ErrInvalidToken).Once()

		userUUID, err := service.VerifyVerificationToken(context.Background(), "verification-token")

		assert.ErrorIs(t, err, services.ErrInvalidToken)
		assert.Empty(t, userUUID)
	})

	service := services.NewEmailVerificationService(services.NewTokenService(tokenSecret), new(mocks.EmailProviderMock), verificationURL)
	sign := func(t *testing.T, claims jwt.MapClaims, secret string) string {
		t.Helper()
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		require.NoError(t, err)
		return token
	}

	t.Run("accepts a token issued for email verification", func(t *testing.T) {
		token := sign(t, jwt.MapClaims{
			"sub": "user-uuid",
			"aud": domain.TokenAudienceEmailVerification,
			"exp": time.Now().Add(time.Hour).Unix(),
		}, tokenSecret)

		userUUID, err := service.VerifyVerificationToken(context.Background(), token)

		require.NoError(t, err)
		assert.Equal(t, "user-uuid", userUUID)
	})

	cases := map[string]string{
		"expired": sign(t, jwt.MapClaims{
			"sub": "user-uuid",
			"aud": domain.TokenAudienceEmailVerification,
			"exp": time.Now().Add(-time.Minute).Unix(),
		}, tokenSecret),
		"wrong audience": sign(t, jwt.MapClaims{
			"sub": "user-uuid",
			"aud": domain.TokenAudienceRefresh,
			"exp": time.Now().Add(time.Hour).Unix(),
		}, tokenSecret),
		"bad signature": sign(t, jwt.MapClaims{
			"sub": "user-uuid",
			"aud": domain.TokenAudienceEmailVerification,
			"exp": time.Now().Add(time.Hour).Unix(),
		}, "different-secret-key"),
		"garbage": "not-a-token",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			userUUID, err := service.VerifyVerificationToken(context.Background(), token)

			assert.ErrorIs(t, err, services.ErrInvalidToken)
			assert.Empty(t, userUUID)
		})
	}
}
