package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWaitGroupWithContext(t *testing.T) {
	t.Run("success - returns nil when the group finishes before the context ends", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		assert.NoError(t, waitGroupWithContext(ctx, &wg))
	})

	t.Run("error - returns the context error when the group outlives the context", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		defer wg.Done()

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		assert.ErrorIs(t, waitGroupWithContext(ctx, &wg), context.DeadlineExceeded)
	})
}
