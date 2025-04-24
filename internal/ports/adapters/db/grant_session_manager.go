package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// GrantSessionManager is a database-backed implementation of the GrantSessionManager interface.
type GrantSessionManager struct {
	db Interface
}

// NewGrantSessionManager creates a new GrantSessionManager instance.
func NewGrantSessionManager(db Interface) *GrantSessionManager {
	return &GrantSessionManager{db: db}
}

func (g *GrantSessionManager) Save(ctx context.Context, session *goidc.GrantSession) error {
	model, err := toGrantSessionModel(session)
	if err != nil {
		return err
	}
	_, err = g.db.ExecContext(
		ctx,
		insertOrUpdateGrantSessionQuery,
		model.ID,
		model.TokenID,
		model.RefreshTokenID,
		model.LastTokenExpiresAtTimestamp,
		model.CreateAtTimestamp,
		model.ExpiresAtTimestamp,
		model.AuthCode,
		model.GrantInfo,
	)
	return err
}

func (g *GrantSessionManager) SessionByTokenID(ctx context.Context, s string) (*goidc.GrantSession, error) {
	var model GrantSession
	err := g.db.QueryRowContext(ctx, findGrantSessionByTokenIDQuery, s).Scan(
		&model.ID,
		&model.TokenID,
		&model.RefreshTokenID,
		&model.LastTokenExpiresAtTimestamp,
		&model.CreateAtTimestamp,
		&model.ExpiresAtTimestamp,
		&model.AuthCode,
		&model.GrantInfo,
	)
	if err != nil {
		return nil, err
	}
	return model.toEntity()
}

func (g *GrantSessionManager) SessionByRefreshTokenID(ctx context.Context, s string) (*goidc.GrantSession, error) {
	var model GrantSession
	err := g.db.QueryRowContext(ctx, findGrantSessionByRefreshTokenIDQuery, s).Scan(
		&model.ID,
		&model.TokenID,
		&model.RefreshTokenID,
		&model.LastTokenExpiresAtTimestamp,
		&model.CreateAtTimestamp,
		&model.ExpiresAtTimestamp,
		&model.AuthCode,
		&model.GrantInfo,
	)
	if err != nil {
		return nil, err
	}
	return model.toEntity()
}

func (g *GrantSessionManager) Delete(ctx context.Context, s string) error {
	_, err := g.db.ExecContext(ctx, deleteGrantSessionQuery, s)
	return err
}

func (g *GrantSessionManager) DeleteByAuthCode(ctx context.Context, s string) error {
	_, err := g.db.ExecContext(ctx, deleteGrantSessionByAuthCodeQuery, s)
	return err
}

/*
 * Model
 */

type GrantSession struct {
	ID                          string
	TokenID                     string
	RefreshTokenID              sql.NullString
	LastTokenExpiresAtTimestamp sql.NullInt64
	CreateAtTimestamp           sql.NullInt64
	ExpiresAtTimestamp          sql.NullInt64
	AuthCode                    sql.NullString
	GrantInfo                   sql.RawBytes
}

func toGrantSessionModel(entity *goidc.GrantSession) (*GrantSession, error) {
	grantInfo, err := json.Marshal(entity.GrantInfo)
	if err != nil {
		return nil, err
	}
	return &GrantSession{
		ID:                          entity.ID,
		TokenID:                     entity.TokenID,
		RefreshTokenID:              toSqlNullString(entity.RefreshTokenID),
		LastTokenExpiresAtTimestamp: toSqlNullInt64(int64(entity.LastTokenExpiresAtTimestamp)),
		CreateAtTimestamp:           toSqlNullInt64(int64(entity.CreatedAtTimestamp)),
		ExpiresAtTimestamp:          toSqlNullInt64(int64(entity.ExpiresAtTimestamp)),
		AuthCode:                    toSqlNullString(entity.AuthCode),
		GrantInfo:                   grantInfo,
	}, nil
}

func (g *GrantSession) toEntity() (*goidc.GrantSession, error) {
	var grantInfo goidc.GrantInfo
	if err := json.Unmarshal(g.GrantInfo, &grantInfo); err != nil {
		return nil, err
	}
	return &goidc.GrantSession{
		ID:                          g.ID,
		TokenID:                     g.TokenID,
		RefreshTokenID:              g.RefreshTokenID.String,
		LastTokenExpiresAtTimestamp: int(g.LastTokenExpiresAtTimestamp.Int64),
		CreatedAtTimestamp:          int(g.CreateAtTimestamp.Int64),
		ExpiresAtTimestamp:          int(g.ExpiresAtTimestamp.Int64),
		AuthCode:                    g.AuthCode.String,
		GrantInfo:                   grantInfo,
	}, nil
}

const (
	insertOrUpdateGrantSessionQuery = `
INSERT INTO AUTH.GRANTED_SESSION (id, token_id, refresh_token_id, last_token_expires_at_timestamp, create_at_timestamp, expires_at_timestamp, auth_code, grant_info)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
		token_id = $2,
		refresh_token_id = $3,
		last_token_expires_at_timestamp = $4,
		create_at_timestamp = $5,
		expires_at_timestamp = $6,
		auth_code = $7,
		grant_info = $8`

	deleteGrantSessionQuery           = `DELETE FROM AUTH.GRANTED_SESSION WHERE id = $1`
	deleteGrantSessionByAuthCodeQuery = `DELETE FROM AUTH.GRANTED_SESSION WHERE auth_code = $1`

	findGrantSessionByTokenIDQuery        = `SELECT * FROM AUTH.GRANTED_SESSION WHERE token_id = $1`
	findGrantSessionByRefreshTokenIDQuery = `SELECT * FROM AUTH.GRANTED_SESSION WHERE refresh_token_id = $1`
)
