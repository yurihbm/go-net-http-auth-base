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

const (
	emailChangeRevertURL = "https://app.test/revert-email-change"
	oauthLinkRevertURL   = "https://app.test/revert-oauth-link"
)

func TestEmailVerificationService_SendEmailChangeCode(t *testing.T) {
	t.Run("sends the code to the new address with a warning not to share it", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(new(mocks.TokenServiceMock), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendEmailChangeCode(context.Background(), "new@example.com", "123456")

		require.NoError(t, err)
		assert.Equal(t, "new@example.com", sent.To)
		assert.Equal(t, "Confirm your new email address", sent.Subject)
		assert.Equal(t, "Your email change code is 123456. Enter it in the browser where you requested the change to confirm it as the email of your account. It expires in 10 minutes. Never share this code with anyone. If you did not request this change, ignore this email.", sent.Text)
		assert.Equal(t, "<p>Your email change code is <strong>123456</strong>. Enter it in the browser where you requested the change to confirm it as the email of your account. It expires in 10 minutes.</p><p>Never share this code with anyone. If you did not request this change, ignore this email.</p>", sent.HTML)
	})

	t.Run("error - returns provider error", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(new(mocks.TokenServiceMock), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		sendErr := errors.New("smtp down")
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(sendErr).Once()

		err := service.SendEmailChangeCode(context.Background(), "new@example.com", "123456")

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestEmailVerificationService_SendEmailChangedNotice(t *testing.T) {
	revert := domain.EmailChangeRevert{UserUUID: "user-uuid", OldEmail: "old@example.com", NewEmail: "new@example.com", Version: 3, ChangedAt: 1700000000}

	t.Run("notifies the previous address with an undo link", func(t *testing.T) {
		tokens := services.NewTokenService(tokenSecret)
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(tokens, emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendEmailChangedNotice(context.Background(), revert)

		require.NoError(t, err)
		assert.Equal(t, "old@example.com", sent.To)
		assert.Equal(t, "Your email address was changed", sent.Subject)
		assert.Contains(t, sent.Text, "new@example.com")
		assert.Contains(t, sent.Text, "If this wasn't you, revert the change and sign out every device")
		assert.Contains(t, sent.HTML, emailChangeRevertURL+"?token=")

		link := regexp.MustCompile(`https://app\.test/revert-email-change\?token=[^\s"<]+`).FindString(sent.Text)
		require.NotEmpty(t, link)
		parsed, err := url.Parse(link)
		require.NoError(t, err)
		got, err := service.VerifyEmailChangeRevertToken(context.Background(), parsed.Query().Get("token"))
		require.NoError(t, err)
		assert.Equal(t, &revert, got)
	})

	t.Run("error - returns token error", func(t *testing.T) {
		tokens := new(mocks.TokenServiceMock)
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(tokens, emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		tokenErr := errors.New("sign failed")
		tokens.On("GenerateToken", mock.Anything).Return("", tokenErr).Once()

		err := service.SendEmailChangedNotice(context.Background(), revert)

		assert.ErrorIs(t, err, tokenErr)
		emailProvider.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
	})

	t.Run("error - returns provider error", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(services.NewTokenService(tokenSecret), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		sendErr := errors.New("smtp down")
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(sendErr).Once()

		err := service.SendEmailChangedNotice(context.Background(), revert)

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestEmailVerificationService_VerifyEmailChangeRevertToken(t *testing.T) {
	service := services.NewEmailVerificationService(services.NewTokenService(tokenSecret), new(mocks.EmailProviderMock), emailChangeRevertURL, oauthLinkRevertURL)
	sign := func(t *testing.T, claims jwt.MapClaims) string {
		t.Helper()
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(tokenSecret))
		require.NoError(t, err)
		return token
	}
	claims := func(aud domain.TokenAudience, payload map[string]any) jwt.MapClaims {
		return jwt.MapClaims{"sub": "user-uuid", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "payload": payload}
	}
	validPayload := func() map[string]any {
		return map[string]any{"old_email": "old@example.com", "new_email": "new@example.com", "ver": 3, "changed_at": 1700000000}
	}

	t.Run("expires after 72 hours", func(t *testing.T) {
		tokens := services.NewTokenService(tokenSecret)
		token, err := tokens.GenerateToken(context.Background(), domain.GenerateTokenDTO{
			Subject:  "user-uuid",
			Audience: domain.TokenAudienceEmailChangeRevert,
		})
		require.NoError(t, err)

		data, err := tokens.VerifyToken(context.Background(), domain.VerifyTokenDTO{Token: token, Audience: domain.TokenAudienceEmailChangeRevert})

		require.NoError(t, err)
		assert.InDelta(t, time.Now().Add(72*time.Hour).Unix(), data.Expiration, 5)
	})

	t.Run("success", func(t *testing.T) {
		got, err := service.VerifyEmailChangeRevertToken(context.Background(), sign(t, claims(domain.TokenAudienceEmailChangeRevert, validPayload())))

		require.NoError(t, err)
		assert.Equal(t, &domain.EmailChangeRevert{UserUUID: "user-uuid", OldEmail: "old@example.com", NewEmail: "new@example.com", Version: 3, ChangedAt: 1700000000}, got)
	})

	without := func(key string) map[string]any {
		payload := validPayload()
		delete(payload, key)
		return payload
	}
	cases := map[string]string{
		"wrong audience":     sign(t, claims(domain.TokenAudienceAccess, validPayload())),
		"missing old email":  sign(t, claims(domain.TokenAudienceEmailChangeRevert, without("old_email"))),
		"missing new email":  sign(t, claims(domain.TokenAudienceEmailChangeRevert, without("new_email"))),
		"missing version":    sign(t, claims(domain.TokenAudienceEmailChangeRevert, without("ver"))),
		"missing changed_at": sign(t, claims(domain.TokenAudienceEmailChangeRevert, without("changed_at"))),
		"garbage":            "not-a-token",
	}
	for name, token := range cases {
		t.Run("error - "+name, func(t *testing.T) {
			got, err := service.VerifyEmailChangeRevertToken(context.Background(), token)

			assert.ErrorIs(t, err, services.ErrInvalidToken)
			assert.Nil(t, got)
		})
	}
}

func TestEmailVerificationService_SendStepUpCode(t *testing.T) {
	t.Run("sends the code to the given address", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(new(mocks.TokenServiceMock), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendStepUpCode(context.Background(), "user@example.com", "123456")

		require.NoError(t, err)
		assert.Equal(t, "user@example.com", sent.To)
		assert.Equal(t, "Your verification code", sent.Subject)
		assert.Equal(t, "Your verification code is 123456. It expires in 10 minutes. If you did not request it, ignore this email.", sent.Text)
		assert.Contains(t, sent.HTML, "<strong>123456</strong>")
	})

	t.Run("error - returns provider error", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(new(mocks.TokenServiceMock), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		sendErr := errors.New("smtp down")
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(sendErr).Once()

		err := service.SendStepUpCode(context.Background(), "user@example.com", "123456")

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestEmailVerificationService_SendSignupCode(t *testing.T) {
	t.Run("sends the code with a warning not to share it", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(new(mocks.TokenServiceMock), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendSignupCode(context.Background(), "new@example.com", "123456")

		require.NoError(t, err)
		assert.Equal(t, "new@example.com", sent.To)
		assert.Equal(t, "Your sign-up code", sent.Subject)
		assert.Equal(t, "Your sign-up code is 123456. Enter it in the browser where you started creating your account. It expires in 10 minutes. Never share this code with anyone. If you did not try to create an account, ignore this email.", sent.Text)
		assert.Equal(t, "<p>Your sign-up code is <strong>123456</strong>. Enter it in the browser where you started creating your account. It expires in 10 minutes.</p><p>Never share this code with anyone. If you did not try to create an account, ignore this email.</p>", sent.HTML)
	})

	t.Run("error - returns provider error", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(new(mocks.TokenServiceMock), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		sendErr := errors.New("smtp down")
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(sendErr).Once()

		err := service.SendSignupCode(context.Background(), "new@example.com", "123456")

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestEmailVerificationService_SendOAuthSignupCode(t *testing.T) {
	t.Run("says the code signs in or links the provider and must not be shared", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(new(mocks.TokenServiceMock), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendOAuthSignupCode(context.Background(), "new@example.com", "123456", domain.OAuthProviderMicrosoft)

		require.NoError(t, err)
		assert.Equal(t, "new@example.com", sent.To)
		assert.Equal(t, "Your sign-in code", sent.Subject)
		assert.Equal(t, "Your sign-in code is 123456. Someone is signing in with a Microsoft account that uses this email. Entering this code signs them in, and the Microsoft account is linked to the account for this email (or a new account is created). Only enter it in the browser where you started signing in. It expires in 10 minutes. Never share this code with anyone. If you did not try to sign in, ignore this email.", sent.Text)
		assert.Equal(t, "<p>Your sign-in code is <strong>123456</strong>. Someone is signing in with a Microsoft account that uses this email. Entering this code signs them in, and the Microsoft account is linked to the account for this email (or a new account is created). Only enter it in the browser where you started signing in. It expires in 10 minutes.</p><p>Never share this code with anyone. If you did not try to sign in, ignore this email.</p>", sent.HTML)
	})

	t.Run("error - returns provider error", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(new(mocks.TokenServiceMock), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		sendErr := errors.New("smtp down")
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(sendErr).Once()

		err := service.SendOAuthSignupCode(context.Background(), "new@example.com", "123456", domain.OAuthProviderGitHub)

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestEmailVerificationService_SendOAuthLinkedNotice(t *testing.T) {
	revert := domain.OAuthLinkRevert{UserUUID: "user-uuid", LinkUUID: "link-uuid", Provider: domain.OAuthProviderGoogle}

	t.Run("notifies the owner with an undo link", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(services.NewTokenService(tokenSecret), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendOAuthLinkedNotice(context.Background(), "owner@example.com", revert)

		require.NoError(t, err)
		assert.Equal(t, "owner@example.com", sent.To)
		assert.Equal(t, "A sign-in provider was linked to your account", sent.Subject)
		assert.Contains(t, sent.Text, "Google was linked to your account. If this wasn't you, undo it")
		assert.Contains(t, sent.HTML, oauthLinkRevertURL+"?token=")

		link := regexp.MustCompile(`https://app\.test/revert-oauth-link\?token=[^\s"<]+`).FindString(sent.Text)
		require.NotEmpty(t, link)
		parsed, err := url.Parse(link)
		require.NoError(t, err)
		got, err := service.VerifyOAuthLinkRevertToken(context.Background(), parsed.Query().Get("token"))
		require.NoError(t, err)
		assert.Equal(t, &revert, got)
	})

	t.Run("escapes the link in the HTML body", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(services.NewTokenService(tokenSecret), emailProvider, emailChangeRevertURL, oauthLinkRevertURL+"?a=1&b=2")
		var sent domain.EmailMessage
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			sent = args.Get(1).(domain.EmailMessage)
		})

		err := service.SendOAuthLinkedNotice(context.Background(), "owner@example.com", revert)

		require.NoError(t, err)
		assert.Contains(t, sent.HTML, "a=1&amp;b=2")
		assert.NotContains(t, sent.HTML, "a=1&b=2")
	})

	t.Run("error - returns token error", func(t *testing.T) {
		tokens := new(mocks.TokenServiceMock)
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(tokens, emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		tokenErr := errors.New("sign failed")
		tokens.On("GenerateToken", mock.Anything).Return("", tokenErr).Once()

		err := service.SendOAuthLinkedNotice(context.Background(), "owner@example.com", revert)

		assert.ErrorIs(t, err, tokenErr)
		emailProvider.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
	})

	t.Run("error - returns provider error", func(t *testing.T) {
		emailProvider := new(mocks.EmailProviderMock)
		service := services.NewEmailVerificationService(services.NewTokenService(tokenSecret), emailProvider, emailChangeRevertURL, oauthLinkRevertURL)
		sendErr := errors.New("smtp down")
		emailProvider.On("Send", mock.Anything, mock.Anything).Return(sendErr).Once()

		err := service.SendOAuthLinkedNotice(context.Background(), "owner@example.com", revert)

		assert.ErrorIs(t, err, sendErr)
	})
}

func TestEmailVerificationService_VerifyOAuthLinkRevertToken(t *testing.T) {
	service := services.NewEmailVerificationService(services.NewTokenService(tokenSecret), new(mocks.EmailProviderMock), emailChangeRevertURL, oauthLinkRevertURL)
	sign := func(t *testing.T, aud domain.TokenAudience, payload map[string]any) string {
		t.Helper()
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user-uuid", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "payload": payload}).SignedString([]byte(tokenSecret))
		require.NoError(t, err)
		return token
	}
	validPayload := func() map[string]any {
		return map[string]any{"link_uuid": "link-uuid", "provider": "github"}
	}

	t.Run("expires after 72 hours", func(t *testing.T) {
		tokens := services.NewTokenService(tokenSecret)
		token, err := tokens.GenerateToken(context.Background(), domain.GenerateTokenDTO{Subject: "user-uuid", Audience: domain.TokenAudienceOAuthLinkRevert})
		require.NoError(t, err)

		data, err := tokens.VerifyToken(context.Background(), domain.VerifyTokenDTO{Token: token, Audience: domain.TokenAudienceOAuthLinkRevert})

		require.NoError(t, err)
		assert.InDelta(t, time.Now().Add(72*time.Hour).Unix(), data.Expiration, 5)
	})

	t.Run("success", func(t *testing.T) {
		got, err := service.VerifyOAuthLinkRevertToken(context.Background(), sign(t, domain.TokenAudienceOAuthLinkRevert, validPayload()))

		require.NoError(t, err)
		assert.Equal(t, &domain.OAuthLinkRevert{UserUUID: "user-uuid", LinkUUID: "link-uuid", Provider: domain.OAuthProviderGitHub}, got)
	})

	without := func(key string) map[string]any {
		payload := validPayload()
		delete(payload, key)
		return payload
	}
	cases := map[string]string{
		"wrong audience":    sign(t, domain.TokenAudienceEmailChangeRevert, validPayload()),
		"missing link uuid": sign(t, domain.TokenAudienceOAuthLinkRevert, without("link_uuid")),
		"missing provider":  sign(t, domain.TokenAudienceOAuthLinkRevert, without("provider")),
		"garbage":           "not-a-token",
	}
	for name, token := range cases {
		t.Run("error - "+name, func(t *testing.T) {
			got, err := service.VerifyOAuthLinkRevertToken(context.Background(), token)

			assert.ErrorIs(t, err, services.ErrInvalidToken)
			assert.Nil(t, got)
		})
	}
}
