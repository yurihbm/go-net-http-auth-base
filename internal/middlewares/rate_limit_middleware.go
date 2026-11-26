package middlewares

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"go-net-http-auth-base/internal/api"
	"go-net-http-auth-base/internal/shared"

	"golang.org/x/time/rate"
)

type RateLimitMiddleware struct {
	visitors map[string]*visitor
	mu       sync.Mutex
	rate     rate.Limit
	burst    int
	now      func() time.Time
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimitMiddleware(ctx context.Context, r rate.Limit, b int) GlobalMiddleware {
	return newRateLimitMiddleware(ctx, r, b, time.Now)
}

func newRateLimitMiddleware(ctx context.Context, r rate.Limit, b int, now func() time.Time) GlobalMiddleware {
	m := &RateLimitMiddleware{
		visitors: make(map[string]*visitor),
		rate:     r,
		burst:    b,
		now:      now,
	}

	go m.cleanupVisitors(ctx)

	return m
}

func (m *RateLimitMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.allow(w, r) {
			next.ServeHTTP(w, r)
		}
	})
}

func (m *RateLimitMiddleware) allow(w http.ResponseWriter, r *http.Request) bool {
	limiter := m.getVisitor(rateLimitKey(shared.ClientIP(r)))
	allowed := limiter.AllowN(m.now(), 1)
	m.setHeaders(w, limiter)
	if !allowed {
		api.WriteJSONResponse(w, http.StatusTooManyRequests, api.ResponseBody[any]{
			Error: "rateLimit.exceeded",
		})
	}
	return allowed
}

// rateLimitKey groups IPv6 clients by /64, since a single subscriber usually controls the whole prefix.
func rateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return prefix.String()
}

func (m *RateLimitMiddleware) getVisitor(ip string) *rate.Limiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	v, exists := m.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(m.rate, m.burst)
		m.visitors[ip] = &visitor{limiter: limiter, lastSeen: m.now()}
		return limiter
	}

	v.lastSeen = m.now()
	return v.limiter
}

func (m *RateLimitMiddleware) cleanupVisitors(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		m.mu.Lock()
		for ip, v := range m.visitors {
			if m.now().Sub(v.lastSeen) > 3*time.Minute {
				delete(m.visitors, ip)
			}
		}
		m.mu.Unlock()
	}
}

func (m *RateLimitMiddleware) setHeaders(w http.ResponseWriter, limiter *rate.Limiter) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(m.burst))

	// TokensAt() returns the number of tokens currently available.
	tokens := limiter.TokensAt(m.now())
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatFloat(tokens, 'f', 0, 64))

	// Calculate time to full replenishment
	// Time = (Burst - CurrentTokens) / Rate
	if m.rate > 0 {
		missingTokens := float64(m.burst) - tokens
		if missingTokens > 0 {
			secondsToFull := missingTokens / float64(m.rate)
			resetTime := m.now().Add(time.Duration(secondsToFull * float64(time.Second))).Unix()
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))
		} else {
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(m.now().Unix(), 10))
		}
	}
}
