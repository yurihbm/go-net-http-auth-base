package domain

import "context"

type Transactor interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}
