package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go-net-http-auth-base/internal/domain"
)

const (
	resendUserAgent        = "go-net-http-auth-base/1.0"
	resendErrorBodyMaxSize = 4096
)

var resendHTTPTimeout = 10 * time.Second

type resendErrorResponse struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

type resendEmailProvider struct {
	apiKey  string
	from    string
	baseURL string
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/emails", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", resendUserAgent)

	client := &http.Client{Timeout: resendHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resendStatusError(resp)
	}
	return nil
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
