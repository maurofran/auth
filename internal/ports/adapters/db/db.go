package db

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/sourcegraph/conc/iter"
	"strings"
	"time"
)

// Querier defines an interface for querying operations with support for context propagation.
// It includes methods to execute queries that return multiple rows or a single row.
// QueryContext executes a query that returns rows, using a context for cancellation.
// QueryRowContext executes a query that is expected to return a single row, using a context for cancellation.
type Querier interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// Executor defines an interface for executing database operations with support for context propagation.
// ExecContext executes a statement that does not return rows, using a context for cancellation.
type Executor interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

// Interface combines the Querier and Executor interfaces for querying and executing database operations.
type Interface interface {
	Querier
	Executor
}

// Scanner is an interface that defines a method for scanning query results into destination variables.
// Scan reads data from the scanner into the provided destination arguments. Returns an error if scanning fails.
type Scanner interface {
	Scan(dest ...interface{}) error
}

// RowsScanner is an interface that extends Scanner with a method to iterate through multiple rows of query results.
type RowsScanner interface {
	Next() bool
	Scanner
}

func toSqlNullInt64(i int64) sql.NullInt64 {
	return sql.NullInt64{Int64: i, Valid: i != 0}
}

func toSqlNullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func toSqlNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: !t.IsZero()}
}

func sliceToString[E fmt.Stringer](value []E) string {
	return strings.Join(iter.Map(value, func(t *E) string {
		return (*t).String()
	}), ",")
}

func stringToSlice[E any](value string, factory func(string) (E, error)) ([]E, error) {
	parts := strings.Split(value, ",")
	result := make([]E, 0, len(parts))
	for _, part := range parts {
		item, err := factory(part)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}
