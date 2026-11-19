package services

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"time"

	"go-net-http-auth-base/internal/domain"
)

type emailVerificationService struct {
	tokens               domain.TokenService
	emailProvider        domain.EmailProvider
	emailChangeURL       string
	emailChangeRevertURL string
}

func NewEmailVerificationService(tokens domain.TokenService, emailProvider domain.EmailProvider, emailChangeURL string, emailChangeRevertURL string) domain.EmailVerificationService {
	return &emailVerificationService{
		tokens:               tokens,
		emailProvider:        emailProvider,
		emailChangeURL:       emailChangeURL,
		emailChangeRevertURL: emailChangeRevertURL,
	}
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
	return s.emailProvider.Send(ctx, codeEmail(email, "Your verification code", "verification code", code,
		"", domain.StepUpCodeTTL,
		"If you did not request it, ignore this email."))
}

func (s *emailVerificationService) SendSignupCode(ctx context.Context, email string, code string) error {
	return s.emailProvider.Send(ctx, codeEmail(email, "Your sign-up code", "sign-up code", code,
		"Enter it in the browser where you started creating your account.", domain.SignupCodeTTL,
		"Never share this code with anyone. If you did not try to create an account, ignore this email."))
}

func codeEmail(to string, subject string, label string, code string, instructions string, ttl time.Duration, warning string) domain.EmailMessage {
	body := fmt.Sprintf("It expires in %d minutes.", int(ttl.Minutes()))
	if instructions != "" {
		body = instructions + " " + body
	}
	return domain.EmailMessage{
		To:      to,
		Subject: subject,
		Text:    fmt.Sprintf("Your %s is %s. %s %s", label, code, body, warning),
		HTML:    fmt.Sprintf("<p>Your %s is <strong>%s</strong>. %s</p><p>%s</p>", label, html.EscapeString(code), html.EscapeString(body), html.EscapeString(warning)),
	}
}

func (s *emailVerificationService) SendOAuthSignupCode(ctx context.Context, email string, code string, provider domain.OAuthProviderName) error {
	minutes := int(domain.SignupCodeTTL.Minutes())
	name := oauthProviderDisplayName(provider)
	return s.emailProvider.Send(ctx, domain.EmailMessage{
		To:      email,
		Subject: "Your sign-in code",
		Text:    fmt.Sprintf("Your sign-in code is %s. Someone is signing in with a %s account that uses this email. Entering this code signs them in, and the %s account is linked to the account for this email (or a new account is created). Only enter it in the browser where you started signing in. It expires in %d minutes. Never share this code with anyone. If you did not try to sign in, ignore this email.", code, name, name, minutes),
		HTML:    fmt.Sprintf("<p>Your sign-in code is <strong>%s</strong>. Someone is signing in with a %s account that uses this email. Entering this code signs them in, and the %s account is linked to the account for this email (or a new account is created). Only enter it in the browser where you started signing in. It expires in %d minutes.</p><p>Never share this code with anyone. If you did not try to sign in, ignore this email.</p>", html.EscapeString(code), name, name, minutes),
	})
}

func oauthProviderDisplayName(provider domain.OAuthProviderName) string {
	switch provider {
	case domain.OAuthProviderGoogle:
		return "Google"
	case domain.OAuthProviderGitHub:
		return "GitHub"
	case domain.OAuthProviderMicrosoft:
		return "Microsoft"
	default:
		return string(provider)
	}
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
