package oidc

import "strings"

type clientCredentialsGrantBasic struct {
	grantType string `schema:"grant_type"`
	scope     string `schema:"scope"`
}

type clientCredentialsGrant struct {
	*clientCredentialsGrantBasic
	clientID     string `schema:"client_id"`
	clientSecret string `schema:"client_secret"`
}

func ClientCredentialsGrantBasic(scopes ...string) *clientCredentialsGrantBasic {
	return &clientCredentialsGrantBasic{
		grantType: "client_credentials",
		scope:     strings.Join(scopes, " "),
	}
}

func ClientCredentialsGrantParams(clientID, clientSecret string, scopes ...string) *clientCredentialsGrant {
	return &clientCredentialsGrant{
		clientCredentialsGrantBasic: ClientCredentialsGrantBasic(scopes...),
		clientID:                    clientID,
		clientSecret:                clientSecret,
	}
}
