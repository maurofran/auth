package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// AuthnSessionManager provides methods for managing authentication sessions in a storage system.
// It interacts with a database through the Interface abstraction for querying and executing operations.
// The type includes functionalities like saving, retrieving, and deleting sessions.
type AuthnSessionManager struct {
	db Interface
}

// NewAuthnSessionManager creates a new instance of AuthnSessionManager.
func NewAuthnSessionManager(db Interface) *AuthnSessionManager {
	return &AuthnSessionManager{db: db}
}

func (a *AuthnSessionManager) Save(ctx context.Context, session *goidc.AuthnSession) error {
	model, err := toAuthnSessionModel(session)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(
		ctx,
		insertOrUpdateAuthnSessionQuery,
		model.ID,
		model.Subject,
		model.ClientID,
		model.PushedAuthReqID,
		model.CallbackID,
		model.CIBAAuthID,
		model.AuthCode,
		model.Value,
	)
	return err
}

func (a *AuthnSessionManager) SessionByCallbackID(ctx context.Context, callbackID string) (*goidc.AuthnSession, error) {
	var model AuthnSession
	err := a.db.QueryRowContext(ctx, findAuthsSessionByCallbackIDQuery, callbackID).Scan(
		&model.ID,
		&model.Subject,
		&model.ClientID,
		&model.PushedAuthReqID,
		&model.CallbackID,
		&model.CIBAAuthID,
		&model.AuthCode,
		&model.Value,
	)
	if err != nil {
		return nil, err
	}
	return model.toEntity()
}

func (a *AuthnSessionManager) SessionByAuthCode(ctx context.Context, authorizationCode string) (*goidc.AuthnSession, error) {
	var model AuthnSession
	err := a.db.QueryRowContext(ctx, findAuthnSessionByAuthCodeQuery, authorizationCode).Scan(
		&model.ID,
		&model.Subject,
		&model.ClientID,
		&model.PushedAuthReqID,
		&model.CallbackID,
		&model.CIBAAuthID,
		&model.AuthCode,
		&model.Value,
	)
	if err != nil {
		return nil, err
	}
	return model.toEntity()
}

func (a *AuthnSessionManager) SessionByPushedAuthReqID(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	var model AuthnSession
	err := a.db.QueryRowContext(ctx, findAuthnSessionByPushedAuthReqIDQuery, id).Scan(
		&model.ID,
		&model.Subject,
		&model.ClientID,
		&model.PushedAuthReqID,
		&model.CallbackID,
		&model.CIBAAuthID,
		&model.AuthCode,
		&model.Value,
	)
	if err != nil {
		return nil, err
	}
	return model.toEntity()
}

func (a *AuthnSessionManager) SessionByCIBAAuthID(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	var model AuthnSession
	err := a.db.QueryRowContext(ctx, findAuthnSessionByCIBAAuthIDQuery, id).Scan(
		&model.ID,
		&model.Subject,
		&model.ClientID,
		&model.PushedAuthReqID,
		&model.CallbackID,
		&model.CIBAAuthID,
		&model.AuthCode,
		&model.Value,
	)
	if err != nil {
		return nil, err
	}
	return model.toEntity()
}

func (a *AuthnSessionManager) Delete(ctx context.Context, id string) error {
	_, err := a.db.ExecContext(ctx, deleteAuthnSessionQuery, id)
	return err
}

/*
 * Model
 */

// AuthnSession represents a session in the database.
type AuthnSession struct {
	ID              string
	Subject         string
	ClientID        string
	PushedAuthReqID sql.NullString
	CallbackID      sql.NullString
	CIBAAuthID      sql.NullString
	AuthCode        sql.NullString
	Value           sql.RawBytes
}

func toAuthnSessionModel(entity *goidc.AuthnSession) (*AuthnSession, error) {
	value, err := json.Marshal(entity)
	if err != nil {
		return nil, err
	}
	return &AuthnSession{
		ID:              entity.ID,
		Subject:         entity.Subject,
		ClientID:        entity.ClientID,
		PushedAuthReqID: toSqlNullString(entity.PushedAuthReqID),
		CallbackID:      toSqlNullString(entity.CallbackID),
		CIBAAuthID:      toSqlNullString(entity.CIBAAuthID),
		AuthCode:        toSqlNullString(entity.AuthCode),
		Value:           value,
	}, nil
}

func (a *AuthnSession) toEntity() (*goidc.AuthnSession, error) {
	var entity goidc.AuthnSession
	err := json.Unmarshal(a.Value, &entity)
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

/*
 * Queries
 */

const (
	insertOrUpdateAuthnSessionQuery = `
INSERT INTO AUTH.AUTHN_SESSION (id, subject, client_id, pushed_auth_req_id, callback_id, ciba_auth_id, auth_code, value)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
	subject = $2,
	client_id = $3,
	pushed_auth_req_id = $4,
	callback_id = $5,
	ciba_auth_id = $6,
	auth_code = $7,
	value = $8`

	findAuthsSessionByCallbackIDQuery      = `SELECT * FROM AUTH.AUTHN_SESSION WHERE callback_id = $1`
	findAuthnSessionByAuthCodeQuery        = `SELECT * FROM AUTH.AUTHN_SESSION WHERE auth_code = $1`
	findAuthnSessionByPushedAuthReqIDQuery = `SELECT * FROM AUTH.AUTHN_SESSION WHERE pushed_auth_req_id = $1`
	findAuthnSessionByCIBAAuthIDQuery      = `SELECT * FROM AUTH.AUTHN_SESSION WHERE ciba_auth_id = $1`

	deleteAuthnSessionQuery = `DELETE FROM AUTH.AUTHN_SESSION WHERE id = $1`
)
