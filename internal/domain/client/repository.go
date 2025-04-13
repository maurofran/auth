package client

import (
	"context"
	"errors"
)

var (
	ErrRegisteredNotFound = errors.New("registered client not found")
	ErrRegisteredExists   = errors.New("registered client already exists")
)

// RegisteredUpdateFn represents a function that processes and updates a Registered entity in a given context.
type RegisteredUpdateFn func(ctx context.Context, entity *Registered) (*Registered, error)

// RegisteredRepository represents a contract for accessing and managing data storage or retrieval systems.
type RegisteredRepository interface {
	// Add inserts a new Registered entity into the repository within the provided context, returning an error if it
	// fails.
	Add(ctx context.Context, entity *Registered) error

	// Update modifies a Registered entity identified by its ID using the provided updater function within the given
	// context.
	Update(ctx context.Context, id int, updaterFn RegisteredUpdateFn) error

	// Remove deletes a Registered entity identified by the given ID from the repository within the provided context.
	Remove(ctx context.Context, id int) error

	// FindByID retrieves a Registered entity by its unique ID from the repository within the given context.
	FindByID(ctx context.Context, id int) (*Registered, error)

	// FindByClientID retrieves a Registered client by its unique ClientID from the repository within the provided
	// context.
	FindByClientID(ctx context.Context, clientID string) (*Registered, error)
}
