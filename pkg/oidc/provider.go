package oidc

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type Provider interface {
	AuthURL(state string) string
	CodeExchange(context.Context, string) (*Tokens, error)
	Authorize(ctx context.Context, accessToken string) //TODO: ???
	Userinfo()
}

type ProviderTokenExchange interface {
	Provider
	TokenExchange(context.Context, TokenExchangeRequest) (*oauth2.Token, error)
}

type TokenExchangeRequest interface {
	SubjectToken() string
	SubjectTokenType() string
	ActorToken() string
	ActorTokenType() string
	Resource() []url.URL //TODO: uri
	Audience() []string
	Scope() []string
	RequestedTokenType() string
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
	JKWsURL       string
}
