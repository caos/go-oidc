package oidc

import (
	"context"
	"time"

	"golang.org/x/oauth2"
)

type Provider interface {
	AuthURL(state string) string
	CodeExchange(context.Context, string) (*Tokens, error)
	Introspect(context.Context, string) (TokenIntrospectResponse, error)
	Authorize(ctx context.Context, accessToken string) //TODO: ???
	Userinfo()
}

type ProviderTokenExchange interface {
	Provider
	TokenExchange(context.Context, *TokenExchangeRequest) (*oauth2.Token, error)
}

// type TokenExchangeRequest interface {
// 	SubjectToken() string
// 	SubjectTokenType() string
// 	ActorToken() string
// 	ActorTokenType() string
// 	Resource() []url.URL //TODO: uri
// 	Audience() []string
// 	Scope() []string
// 	RequestedTokenType() string

// 	MarschalForm() url.Values
// }

type TokenIntrospectResponse interface {
	Active() bool
	Scope() string
	ClientID() string
	Username() string
	TokenType() string //TODO: typed?
	Expiration() time.Time
	IssuedAt() time.Time
	NotBefore() time.Time
	Subject() string
	Audience() []string
	Issuer() string
	JWTID() string
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
