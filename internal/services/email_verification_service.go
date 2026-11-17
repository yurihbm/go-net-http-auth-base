package services

import (
	"context"
	"fmt"
	"html"
	"net/url"

	"go-net-http-auth-base/internal/domain"
)

type emailVerificationService struct {
	tokens               domain.TokenService
	emailProvider        domain.EmailProvider
	verificationURL      string
	emailChangeURL       string
	emailChangeRevertURL string
}

func NewEmailVerificationService(tokens domain.TokenService, emailProvider domain.EmailProvider, verificationURL string, emailChangeURL string, emailChangeRevertURL string) domain.EmailVerificationService {
	return &emailVerificationService{
		tokens:               tokens,
		emailProvider:        emailProvider,
		verificationURL:      verificationURL,
		emailChangeURL:       emailChangeURL,
		emailChangeRevertURL: emailChangeRevertURL,
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
		Payload: map[string]any{
			"current_email": user.Email,
			"new_email":     newEmail,
			"ver":           user.EmailVersion,
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
	version, ok := payload["ver"].(float64)
	if currentEmail == "" || newEmail == "" || !ok {
		return nil, ErrInvalidToken
	}

	return &domain.EmailChange{
		UserUUID:     tokenData.Subject,
		CurrentEmail: currentEmail,
		NewEmail:     newEmail,
		Version:      int(version),
	}, nil
}

func (s *emailVerificationService) SendEmailChangedNotice(ctx context.Context, revert domain.EmailChangeRevert) error {
	link, err := s.tokenLink(ctx, s.emailChangeRevertURL, domain.GenerateTokenDTO{
		Subject:  revert.UserUUID,
		Audience: domain.TokenAudienceEmailChangeRevert,
		Payload: map[string]any{
			"old_email":  revert.OldEmail,
			"new_email":  revert.NewEmail,
			"ver":        revert.Version,
			"changed_at": revert.ChangedAt,
		},
	})
	if err != nil {
		return err
	}

	return s.emailProvider.Send(ctx, domain.EmailMessage{
		To:      revert.OldEmail,
		Subject: "Your email address was changed",
		Text:    fmt.Sprintf("The email address of your account was changed to %s. If this wasn't you, revert the change and sign out every device by opening this link: %s", revert.NewEmail, link),
		HTML:    fmt.Sprintf(`<p>The email address of your account was changed to %s. If this wasn't you, <a href="%s">revert the change and sign out every device</a>.</p>`, html.EscapeString(revert.NewEmail), html.EscapeString(link)),
	})
}

func (s *emailVerificationService) VerifyEmailChangeRevertToken(ctx context.Context, token string) (*domain.EmailChangeRevert, error) {
	tokenData, err := s.tokens.VerifyToken(ctx, domain.VerifyTokenDTO{
		Token:    token,
		Audience: domain.TokenAudienceEmailChangeRevert,
	})
	if err != nil {
		return nil, err
	}

	payload, _ := tokenData.Payload.(map[string]any)
	oldEmail, _ := payload["old_email"].(string)
	newEmail, _ := payload["new_email"].(string)
	version, hasVersion := payload["ver"].(float64)
	changedAt, hasChangedAt := payload["changed_at"].(float64)
	if oldEmail == "" || newEmail == "" || !hasVersion || !hasChangedAt {
		return nil, ErrInvalidToken
	}

	return &domain.EmailChangeRevert{
		UserUUID:  tokenData.Subject,
		OldEmail:  oldEmail,
		NewEmail:  newEmail,
		Version:   int(version),
		ChangedAt: int64(changedAt),
	}, nil
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
