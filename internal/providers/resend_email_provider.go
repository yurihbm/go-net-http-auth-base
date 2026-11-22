package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go-net-http-auth-base/internal/domain"

	"github.com/google/uuid"
)

const (
	resendUserAgent        = "go-net-http-auth-base/1.0"
	resendErrorBodyMaxSize = 4096
	resendHTTPTimeout      = 10 * time.Second
	resendMaxAttempts      = 3
	resendBackoff          = 200 * time.Millisecond
	resendMaxBackoff       = 2 * time.Second
)

type resendErrorResponse struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

type resendEmailProvider struct {
	apiKey  string
	from    string
	baseURL string
	client  *http.Client
	wait    func(ctx context.Context, d time.Duration) error
}

type resendEmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html,omitempty"`
	Text    string   `json:"text,omitempty"`
}

func NewResendEmailProvider(apiKey string, from string, baseURL ...string) domain.EmailProvider {
	urlToUse := "https://api.resend.com"
	if len(baseURL) > 0 && baseURL[0] != "" {
		urlToUse = baseURL[0]
	}
	return &resendEmailProvider{
		apiKey:  apiKey,
		from:    from,
		baseURL: urlToUse,
		client:  &http.Client{Timeout: resendHTTPTimeout},
		wait:    waitWithContext,
	}
}

func waitWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *resendEmailProvider) Send(ctx context.Context, msg domain.EmailMessage) error {
	body, err := json.Marshal(resendEmailRequest{
		From:    p.from,
		To:      []string{msg.To},
		Subject: msg.Subject,
		HTML:    msg.HTML,
		Text:    msg.Text,
	})
	if err != nil {
		return err
	}

	idempotencyKey, err := uuid.NewV7()
	if err != nil {
		return err
	}

	for attempt := 1; ; attempt++ {
		retryAfter, retryable, err := p.attempt(ctx, body, idempotencyKey.String())
		if err == nil || !retryable || attempt == resendMaxAttempts || ctx.Err() != nil {
			return err
		}

		delay := resendBackoff << (attempt - 1)
		if retryAfter > 0 && retryAfter <= resendMaxBackoff {
			delay = retryAfter
		}
		if waitErr := p.wait(ctx, delay); waitErr != nil {
			return waitErr
		}
	}
}

func (p *resendEmailProvider) attempt(ctx context.Context, body []byte, idempotencyKey string) (time.Duration, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/emails", bytes.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", resendUserAgent)
	req.Header.Set("Idempotency-Key", idempotencyKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, true, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return 0, false, nil
	}

	retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	var retryAfter time.Duration
	if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
		retryAfter = time.Duration(seconds) * time.Second
	}
	return retryAfter, retryable, resendStatusError(resp)
}

func resendStatusError(resp *http.Response) error {
	var detail resendErrorResponse
	raw, err := io.ReadAll(io.LimitReader(resp.Body, resendErrorBodyMaxSize))
	if err == nil && json.Unmarshal(raw, &detail) == nil {
		var parts []string
		for _, part := range []string{detail.Name, detail.Message} {
			if part != "" {
				parts = append(parts, part)
			}
		}
		if len(parts) > 0 {
			return fmt.Errorf("resend: unexpected status %d: %s", resp.StatusCode, strings.Join(parts, ": "))
		}
	}
	return fmt.Errorf("resend: unexpected status %d", resp.StatusCode)
}
