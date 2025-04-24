package session

import "context"

// User represents an authenticated user with identifying and session-related information.
type User struct {
	ID       string
	Subject  string
	AuthTime int
}

// Store represents a session storage interface providing methods for storing and retrieving user sessions.
// Put adds or updates a user session identified by a unique ID.
// Get retrieves a user session associated with a given ID.
type Store interface {
	Put(ctx context.Context, id string, session *User) error
	Get(ctx context.Context, id string) (*User, error)
}
