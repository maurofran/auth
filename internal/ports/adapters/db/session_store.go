package db

import (
	"context"
	"github.com/maurofran/auth/internal/domain/session"
)

// SessionStore is a type that provides storage and management for session-related data using a database interface.
type SessionStore struct {
	db Interface
}

// NewSessionStore initializes and returns a new instance of SessionStore with the provided database interface.
func NewSessionStore(db Interface) *SessionStore {
	return &SessionStore{db: db}
}

func (s *SessionStore) Put(ctx context.Context, id string, session *session.User) error {
	_, err := s.db.ExecContext(ctx, insertSessionQuery, id, session.Subject, session.AuthTime)
	return err
}

func (s *SessionStore) Get(ctx context.Context, id string) (*session.User, error) {
	var user session.User
	err := s.db.QueryRowContext(ctx, selectSessionQuery, id).Scan(&user.ID, &user.Subject, &user.AuthTime)
	return &user, err
}

const (
	insertSessionQuery = `INSERT INTO AUTH.USER_SESSION (id, subject, auth_time) VALUES ($1, $2, $3)`
	selectSessionQuery = `SELECT id, subject, auth_time FROM AUTH.USER_SESSION WHERE id = $1`
)
