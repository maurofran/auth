package iam

import (
	"encoding/json"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"time"
)

func unixNow() int {
	return int(time.Now().Unix())
}

func addClaim(session *goidc.AuthnSession, claimName string) {
	if claim, ok := session.Claims.IDToken[claimName]; ok {
		session.SetIDTokenClaim(goidc.ClaimEmail, claim.Value)
	}
	if claim, ok := session.Claims.UserInfo[claimName]; ok {
		session.SetUserInfoClaim(goidc.ClaimEmail, claim.Value)
	}
}

func addClaimValue(session *goidc.AuthnSession, claimName string, value any) {
	if _, ok := session.Claims.IDToken[claimName]; ok {
		session.SetIDTokenClaim(goidc.ClaimEmail, value)
	}
	if _, ok := session.Claims.UserInfo[claimName]; ok {
		session.SetUserInfoClaim(goidc.ClaimEmail, value)
	}
}

func sessionToMap(as *goidc.AuthnSession) map[string]any {
	data, _ := json.Marshal(as)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return m
}
