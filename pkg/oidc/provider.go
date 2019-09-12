package oidc

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

type Provider interface {
	AuthURL(state string) string
	AuthURLHandler(state string) http.HandlerFunc
	CodeExchange(ctx context.Context, code string) (*Tokens, error)
	CodeExchangeHandler(callback func(http.ResponseWriter, *http.Request, *Tokens, string)) http.HandlerFunc
	ClientCredentials(ctx context.Context, scopes ...string) (*oauth2.Token, error)
	Introspect(ctx context.Context, token string) (TokenIntrospectResponse, error)
	// Authorize(ctx context.Context, accessToken string) //TODO: ???
	Userinfo()
}

type ProviderExtension interface {
	Provider
	PasswordGrant(context.Context, string, string) (*oauth2.Token, error)
}

type ProviderTokenExchange interface {
	Provider
	TokenExchange(context.Context, *TokenExchangeRequest) (*oauth2.Token, error)
}

type ProviderDelegationTokenExchange interface {
	ProviderTokenExchange
	DelegationTokenExchange(context.Context, string, ...TokenExchangeOption) (*oauth2.Token, error)
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
