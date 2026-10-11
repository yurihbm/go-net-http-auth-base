package repositories

import (
	"context"

	"go-net-http-auth-base/internal/domain"
	"go-net-http-auth-base/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type txContextKey struct{}

type PostgresTransactor struct {
	pool *pgxpool.Pool
}

var _ domain.Transactor = (*PostgresTransactor)(nil)

func NewPostgresTransactor(pool *pgxpool.Pool) *PostgresTransactor {
	return &PostgresTransactor{pool: pool}
}

func (t *PostgresTransactor) WithinTx(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if _, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok {
		return fn(ctx)
	}

	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return err
	}

	rollback := func() {
		_ = tx.Rollback(context.WithoutCancel(ctx))
	}

	defer func() {
		if r := recover(); r != nil {
			rollback()
			panic(r)
		}
	}()

	if err := fn(context.WithValue(ctx, txContextKey{}, tx)); err != nil {
		rollback()
		return err
	}

	return tx.Commit(ctx)
}

type TxAwareDB struct {
	pool *pgxpool.Pool
}

var _ postgres.DBTX = (*TxAwareDB)(nil)

func NewTxAwareDB(pool *pgxpool.Pool) *TxAwareDB {
	return &TxAwareDB{pool: pool}
}

func (d *TxAwareDB) executor(ctx context.Context) postgres.DBTX {
	if tx, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok {
		return tx
	}
	return d.pool
}

func (d *TxAwareDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return d.executor(ctx).Exec(ctx, sql, args...)
}

func (d *TxAwareDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return d.executor(ctx).Query(ctx, sql, args...)
}

func (d *TxAwareDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return d.executor(ctx).QueryRow(ctx, sql, args...)
}
