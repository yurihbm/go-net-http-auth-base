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
	emailChangeURL  string
}

func NewEmailVerificationService(tokens domain.TokenService, emailProvider domain.EmailProvider, verificationURL string, emailChangeURL string) domain.EmailVerificationService {
	return &emailVerificationService{
		tokens:          tokens,
		emailProvider:   emailProvider,
		verificationURL: verificationURL,
		emailChangeURL:  emailChangeURL,
	}
}

func (s *emailVerificationService) SendVerificationEmail(ctx context.Context, user *domain.User) error {
	link, err := s.tokenLink(ctx, s.verificationURL, domain.GenerateTokenDTO{
		Subject:  user.UUID,
		Audience: domain.TokenAudienceEmailVerification,
	})
	if err != nil {
		return err
	}

	return s.emailProvider.Send(ctx, domain.EmailMessage{
		To:      user.Email,
		Subject: "Verify your email address",
		Text:    fmt.Sprintf("Verify your email address by opening this link: %s", link),
		HTML:    fmt.Sprintf(`<p>Verify your email address by clicking <a href="%s">this link</a>.</p>`, html.EscapeString(link)),
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

func (s *emailVerificationService) SendEmailChangeEmail(ctx context.Context, user *domain.User, newEmail string) error {
	link, err := s.tokenLink(ctx, s.emailChangeURL, domain.GenerateTokenDTO{
		Subject:  user.UUID,
		Audience: domain.TokenAudienceEmailChange,
		Payload: map[string]string{
			"current_email": user.Email,
			"new_email":     newEmail,
		},
	})
	if err != nil {
		return err
	}

	return s.emailProvider.Send(ctx, domain.EmailMessage{
		To:      newEmail,
		Subject: "Confirm your new email address",
		Text:    fmt.Sprintf("Confirm your new email address by opening this link: %s", link),
		HTML:    fmt.Sprintf(`<p>Confirm your new email address by clicking <a href="%s">this link</a>.</p>`, html.EscapeString(link)),
	})
}

func (s *emailVerificationService) VerifyEmailChangeToken(ctx context.Context, token string) (*domain.EmailChange, error) {
	tokenData, err := s.tokens.VerifyToken(ctx, domain.VerifyTokenDTO{
		Token:    token,
		Audience: domain.TokenAudienceEmailChange,
	})
	if err != nil {
		return nil, err
	}

	payload, _ := tokenData.Payload.(map[string]any)
	currentEmail, _ := payload["current_email"].(string)
	newEmail, _ := payload["new_email"].(string)
	if currentEmail == "" || newEmail == "" {
		return nil, ErrInvalidToken
	}

	return &domain.EmailChange{
		UserUUID:     tokenData.Subject,
		CurrentEmail: currentEmail,
		NewEmail:     newEmail,
	}, nil
}

func (s *emailVerificationService) SendEmailChangedNotice(ctx context.Context, oldEmail string, newEmail string) error {
	return s.emailProvider.Send(ctx, domain.EmailMessage{
		To:      oldEmail,
		Subject: "Your email address was changed",
		Text:    fmt.Sprintf("The email address of your account was changed to %s. If you did not make this change, contact support.", newEmail),
		HTML:    fmt.Sprintf("<p>The email address of your account was changed to %s. If you did not make this change, contact support.</p>", html.EscapeString(newEmail)),
	})
}

func (s *emailVerificationService) SendStepUpCode(ctx context.Context, email string, code string) error {
	return s.emailProvider.Send(ctx, domain.EmailMessage{
		To:      email,
		Subject: "Your verification code",
		Text:    fmt.Sprintf("Your verification code is %s. It expires in %d minutes. If you did not request it, ignore this email.", code, int(domain.StepUpCodeTTL.Minutes())),
		HTML:    fmt.Sprintf("<p>Your verification code is <strong>%s</strong>. It expires in %d minutes. If you did not request it, ignore this email.</p>", html.EscapeString(code), int(domain.StepUpCodeTTL.Minutes())),
	})
}

func (s *emailVerificationService) tokenLink(ctx context.Context, baseURL string, dto domain.GenerateTokenDTO) (string, error) {
	token, err := s.tokens.GenerateToken(ctx, dto)
	if err != nil {
		return "", err
	}

	link, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	query := link.Query()
	query.Set("token", token)
	link.RawQuery = query.Encode()

	return link.String(), nil
}
