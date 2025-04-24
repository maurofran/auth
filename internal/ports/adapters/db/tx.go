package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

// Transactor defines an interface for beginning a database transaction with context and transaction options.
type Transactor interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// Transaction represents a database transaction with commit and rollback functionalities.
type Transaction interface {
	Commit() error
	Rollback() error
}

func runInTransaction(ctx context.Context, db Interface, fn func(tx Interface) error) error {
	if txDB, ok := db.(Transactor); ok {
		slog.DebugContext(ctx, "Provided db is a transactor, starting a new transaction")

		tx, err := txDB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		slog.DebugContext(ctx, "Invoking callback fn with transaction")

		err = fn(tx)
		if err == nil {
			slog.DebugContext(ctx, "Committing transaction")

			return tx.Commit()
		}
		slog.DebugContext(ctx, "Rolling back transaction")

		rollbackErr := tx.Rollback()
		return errors.Join(err, rollbackErr)
	}
	if _, ok := db.(Transaction); ok {
		slog.DebugContext(ctx, "A transaction is already running, invoking callback fn")

		return fn(db)
	}
	return fmt.Errorf("db is not a transactor or transaction")
}
