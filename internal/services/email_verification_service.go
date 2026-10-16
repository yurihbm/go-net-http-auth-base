package services

import (
	"context"
	"fmt"
	"html"
	"net/url"

	"go-net-http-auth-base/internal/domain"
)

type emailVerificationService struct {
	tokens          domain.TokenService
	emailProvider   domain.EmailProvider
	verificationURL string
}

func NewEmailVerificationService(tokens domain.TokenService, emailProvider domain.EmailProvider, verificationURL string) domain.EmailVerificationService {
	return &emailVerificationService{
		tokens:          tokens,
		emailProvider:   emailProvider,
		verificationURL: verificationURL,
	}
}

func (s *emailVerificationService) SendVerificationEmail(ctx context.Context, user *domain.User) error {
	token, err := s.tokens.GenerateToken(ctx, domain.GenerateTokenDTO{
		Subject:  user.UUID,
		Audience: domain.TokenAudienceEmailVerification,
	})
	if err != nil {
		return err
	}

	link, err := url.Parse(s.verificationURL)
	if err != nil {
		return err
	}
	query := link.Query()
	query.Set("token", token)
	link.RawQuery = query.Encode()

	return s.emailProvider.Send(ctx, domain.EmailMessage{
		To:      user.Email,
		Subject: "Verify your email address",
		Text:    fmt.Sprintf("Verify your email address by opening this link: %s", link.String()),
		HTML:    fmt.Sprintf(`<p>Verify your email address by clicking <a href="%s">this link</a>.</p>`, html.EscapeString(link.String())),
	})
}

func (s *emailVerificationService) VerifyVerificationToken(ctx context.Context, token string) (string, error) {
	tokenData, err := s.tokens.VerifyToken(ctx, domain.VerifyTokenDTO{
		Token:    token,
		Audience: domain.TokenAudienceEmailVerification,
	})
	if err != nil {
		return "", err
	}

	return tokenData.Subject, nil
}
