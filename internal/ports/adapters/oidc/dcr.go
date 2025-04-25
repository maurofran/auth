package oidc

import (
	"github.com/luikyv/go-oidc/pkg/goidc"
	"net/http"
	"slices"
	"strings"
)

func dcrHandler(_ *http.Request, _ string, meta *goidc.ClientMetaInfo) error {
	var s []string
	for _, scope := range allScopes {
		s = append(s, scope.ID)
	}
	meta.ScopeIDs = strings.Join(s, " ")

	if !slices.Contains(meta.GrantTypes, goidc.GrantRefreshToken) {
		meta.GrantTypes = append(meta.GrantTypes, goidc.GrantRefreshToken)
	}

	return nil
}

func dcrValidator(_ *http.Request, _ string) error {
	return nil
}
