package middlewares

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimitMiddleware struct {
	visitors map[string]*visitor
	mu       sync.Mutex
	rate     rate.Limit
	burst    int
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimitMiddleware(r rate.Limit, b int) GlobalMiddleware {
	m := &RateLimitMiddleware{
		visitors: make(map[string]*visitor),
		rate:     r,
		burst:    b,
	}

	go m.cleanupVisitors()

	return m
}

func (m *RateLimitMiddleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		limiter := m.getVisitor(ip)

		if !limiter.Allow() {
			m.setHeaders(w, limiter)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		m.setHeaders(w, limiter)
		next.ServeHTTP(w, r)
	})
}

func (m *RateLimitMiddleware) getVisitor(ip string) *rate.Limiter {
	m.mu.Lock()
	defer m.mu.Unlock()

	v, exists := m.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(m.rate, m.burst)
		m.visitors[ip] = &visitor{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (m *RateLimitMiddleware) cleanupVisitors() {
	for {
		time.Sleep(time.Minute)

		m.mu.Lock()
		for ip, v := range m.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(m.visitors, ip)
			}
		}
		m.mu.Unlock()
	}
}

func (m *RateLimitMiddleware) setHeaders(w http.ResponseWriter, limiter *rate.Limiter) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(m.burst))

	// Tokens() returns the number of tokens currently available.
	tokens := limiter.Tokens()
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatFloat(tokens, 'f', 0, 64))

	// Calculate time to full replenishment
	// Time = (Burst - CurrentTokens) / Rate
	if m.rate > 0 {
		missingTokens := float64(m.burst) - tokens
		if missingTokens > 0 {
			secondsToFull := missingTokens / float64(m.rate)
			resetTime := time.Now().Add(time.Duration(secondsToFull * float64(time.Second))).Unix()
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))
		} else {
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Unix(), 10))
		}
	}
}
