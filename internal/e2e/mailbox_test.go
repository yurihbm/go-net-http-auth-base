package e2e_test

import (
	"context"
	"net/url"
	"regexp"
	"sync"
	"testing"

	"go-net-http-auth-base/internal/domain"

	"github.com/stretchr/testify/require"
)

var stepUpCodePattern = regexp.MustCompile(`code is (\d{6})`)

type capturingEmailProvider struct {
	mu       sync.Mutex
	messages map[string]domain.EmailMessage
}

var _ domain.EmailProvider = (*capturingEmailProvider)(nil)

func newCapturingEmailProvider() *capturingEmailProvider {
	return &capturingEmailProvider{messages: map[string]domain.EmailMessage{}}
}

func (p *capturingEmailProvider) Send(_ context.Context, msg domain.EmailMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.messages[msg.To] = msg
	return nil
}

func (p *capturingEmailProvider) last(t *testing.T, to string) domain.EmailMessage {
	t.Helper()

	p.mu.Lock()
	defer p.mu.Unlock()
	msg, ok := p.messages[to]
	require.True(t, ok, "no email sent to %s", to)
	return msg
}

func (p *capturingEmailProvider) stepUpCode(t *testing.T, to string) string {
	t.Helper()

	match := stepUpCodePattern.FindStringSubmatch(p.last(t, to).Text)
	require.Len(t, match, 2, "no step-up code in the email to %s", to)
	return match[1]
}

func (p *capturingEmailProvider) linkToken(t *testing.T, to string) string {
	t.Helper()

	text := p.last(t, to).Text
	link := regexp.MustCompile(`https?://\S+`).FindString(text)
	require.NotEmpty(t, link, "no link in the email to %s", to)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	token := parsed.Query().Get("token")
	require.NotEmpty(t, token)
	return token
}
