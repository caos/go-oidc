package oidc

import (
	"context"

	"golang.org/x/oauth2"
)

type Provider interface {
	CodeExchange(ctx context.Context, code string) (accessToken string, err error)
	Authorize(ctx context.Context, accessToken string)
	Userinfo()
}

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
	Issuer       string
	Scopes       []string
}

type ProviderOptionFunc func(Provider)

type Endpoints struct {
	oauth2.Endpoint
	IntrospectURL string
	UserinfoURL   string
	jkwsURL       string
}
