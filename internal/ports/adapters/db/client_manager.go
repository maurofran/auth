package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// ClientManager provides methods for managing clients in a storage system.
// It interacts with a database through the Interface abstraction for querying and executing operations.
// The type includes functionalities like saving, retrieving, and deleting clients.
type ClientManager struct {
	db Interface
}

// NewClientManager creates and returns a new ClientManager with the provided database interface.
func NewClientManager(db Interface) *ClientManager {
	return &ClientManager{db: db}
}

func (c *ClientManager) Save(ctx context.Context, client *goidc.Client) error {
	model, err := toClientModel(client)
	if err != nil {
		return err
	}
	_, err = c.db.ExecContext(
		ctx,
		insertOrUpdateClientQuery,
		model.ID,
		model.Secret,
		model.HashedSecret,
		model.HashedRegistrationToken,
		model.RegistrationType,
		model.ExpiresAt,
		model.ClientMetaInfo,
	)
	return err
}

func (c *ClientManager) Client(ctx context.Context, id string) (*goidc.Client, error) {
	var model Client
	err := c.db.QueryRowContext(ctx, findClientQuery, id).Scan(
		&model.ID,
		&model.Secret,
		&model.HashedSecret,
		&model.HashedRegistrationToken,
		&model.RegistrationType,
		&model.ExpiresAt,
		&model.ClientMetaInfo,
	)
	if err != nil {
		return nil, err
	}
	return model.toEntity()
}

func (c *ClientManager) Delete(ctx context.Context, id string) error {
	_, err := c.db.ExecContext(ctx, deleteClientQuery, id)
	return err
}

/*
 * Models
 */

type Client struct {
	ID                      string
	Secret                  sql.NullString
	HashedSecret            sql.NullString
	HashedRegistrationToken sql.NullString
	RegistrationType        sql.NullString
	ExpiresAt               sql.NullInt64
	ClientMetaInfo          sql.RawBytes
}

func toClientModel(entity *goidc.Client) (*Client, error) {
	clientMetaInfo, err := json.Marshal(entity.ClientMetaInfo)
	if err != nil {
		return nil, err
	}
	expiresAt := sql.NullInt64{Valid: entity.ExpiresAt != nil}
	if expiresAt.Valid {
		expiresAt.Int64 = int64(*entity.ExpiresAt)
	}
	return &Client{
		ID:                      entity.ID,
		Secret:                  toSqlNullString(entity.Secret),
		HashedSecret:            toSqlNullString(entity.HashedSecret),
		HashedRegistrationToken: toSqlNullString(entity.HashedRegistrationToken),
		RegistrationType:        toSqlNullString(string(entity.RegistrationType)),
		ExpiresAt:               expiresAt,
		ClientMetaInfo:          clientMetaInfo,
	}, nil
}

func (c *Client) toEntity() (*goidc.Client, error) {
	var entity goidc.Client
	err := json.Unmarshal(c.ClientMetaInfo, &entity.ClientMetaInfo)
	if err != nil {
		return nil, err
	}
	entity.ID = c.ID
	entity.Secret = c.Secret.String
	entity.HashedSecret = c.HashedSecret.String
	entity.HashedRegistrationToken = c.HashedRegistrationToken.String
	entity.RegistrationType = goidc.ClientRegistrationType(c.RegistrationType.String)
	if c.ExpiresAt.Valid {
		expiresAt := int(c.ExpiresAt.Int64)
		entity.ExpiresAt = &expiresAt
	}
	return &entity, nil
}

/*
 * Queries
 */

const (
	insertOrUpdateClientQuery = `
INSERT INTO AUTH.CLIENT (id, secret, hashed_secret, hashed_registration_token, registration_type, expires_at, client_meta_info)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
	secret = $2,
	hashed_secret = $3,
	hashed_registration_token = $4,
	registration_type = $5,
	expires_at = $6,
	client_meta_info = $7`

	findClientQuery = `SELECT id, secret, hashed_secret, hashed_registration_token, registration_type, expires_at, client_meta_info FROM AUTH.CLIENT WHERE id = $1`

	deleteClientQuery = `DELETE FROM AUTH.CLIENT WHERE id = $1`
)
